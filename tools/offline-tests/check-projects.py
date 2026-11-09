#!/usr/bin/env python3
"""Compiles each test project on its own, NuGet-free (xUnit shim instead of packages), so that a file one
project uses but does not include is caught before CI. Projects that need NuGet-only packages are skipped.
Usage: python3 tools/offline-tests/check-projects.py"""
import os, re, subprocess, sys, tempfile, xml.etree.ElementTree as ET

root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
shim = os.path.join(root, 'tools', 'offline-tests', 'XunitShim.cs')
skip_refs = ('XINSkan.Storage', 'XINSkan.App')   # need Microsoft.Data.Sqlite / WPF
failed = []
for name in sorted(os.listdir(os.path.join(root, 'tests'))):
    proj = os.path.join(root, 'tests', name, name + '.csproj')
    if not os.path.exists(proj) or name == 'XINSkan.NegativeBuild':
        continue
    tree = ET.parse(proj)
    refs = [r.get('Include') for r in tree.iter('ProjectReference')]
    if any(s in r for r in refs for s in skip_refs):
        print(f'skip  {name} (needs NuGet-only packages)')
        continue
    pdir = os.path.dirname(proj)
    links = [os.path.normpath(os.path.join(pdir, c.get('Include').replace('\\', '/'))) for c in tree.iter('Compile') if c.get('Include')]
    resources = [c.get('Include').replace('\\', '/') for c in tree.iter('EmbeddedResource') if c.get('Include')]
    work = tempfile.mkdtemp(prefix='xinskan-check-')
    items = '\n'.join(f'    <Compile Include="{l}" />' for l in links)
    items += f'\n    <Compile Include="{pdir}/**/*.cs" Exclude="{pdir}/obj/**;{pdir}/bin/**" />'
    items += f'\n    <Compile Include="{shim}" />'
    items += ''.join(f'\n    <EmbeddedResource Include="{os.path.normpath(os.path.join(pdir, r))}" LogicalName="%(Filename)%(Extension)" />' for r in resources)
    prefs = '\n'.join(f'    <ProjectReference Include="{os.path.normpath(os.path.join(pdir, r.replace(chr(92), "/")))}" />' for r in refs)
    with open(os.path.join(work, 'Check.csproj'), 'w') as f:
        f.write(f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType><XinOffline>true</XinOffline>
  <XinEnforceReadOnly>false</XinEnforceReadOnly><EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  <AssemblyName>{name}</AssemblyName><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings>
  <NoWarn>$(NoWarn);CA1707;CA1515;CA2000;CA1861;CA1720</NoWarn></PropertyGroup>
  <ItemGroup><Using Include="Xunit" /><Using Include="Xunit.Abstractions" /></ItemGroup>
  <ItemGroup>
{items}
  </ItemGroup>
  <ItemGroup>
{prefs}
  </ItemGroup>
</Project>''')
    r = subprocess.run(['dotnet', 'build', os.path.join(work, 'Check.csproj'), '-p:XinOffline=true', '-nologo', '-v:q'], capture_output=True, text=True)
    errors = sorted(set(l.strip() for l in r.stdout.splitlines() if ' error ' in l and 'XunitShim' not in l))
    if r.returncode != 0 and errors:
        failed.append(name)
        print(f'FAIL  {name}')
        for e in errors[:10]:
            print('      ' + e[:240])
    else:
        print(f'ok    {name}')
sys.exit(1 if failed else 0)
