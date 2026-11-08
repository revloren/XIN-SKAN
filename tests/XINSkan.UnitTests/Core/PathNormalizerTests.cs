using XINSkan.Core.Paths;

namespace XINSkan.UnitTests.Core;

public class PathNormalizerTests
{
    [Theory]
    [InlineData(@"C:\Users\Player\.minecraft\mods\Client.jar", @"C:\USERS\PLAYER\.MINECRAFT\MODS\CLIENT.JAR")]
    [InlineData(@"c:/users/player/.minecraft/mods/client.jar", @"C:\USERS\PLAYER\.MINECRAFT\MODS\CLIENT.JAR")]
    [InlineData(@"\\?\C:\Users\Player\file.jar", @"C:\USERS\PLAYER\FILE.JAR")]
    [InlineData(@"\??\C:\Users\Player\file.jar", @"C:\USERS\PLAYER\FILE.JAR")]
    [InlineData(@"\\.\C:\Users\Player\file.jar", @"C:\USERS\PLAYER\FILE.JAR")]
    [InlineData(@"\\?\UNC\server\share\x.jar", @"\\SERVER\SHARE\X.JAR")]
    [InlineData(@"\\server\share\dir\..\x.jar", @"\\SERVER\SHARE\X.JAR")]
    [InlineData(@"C:\Users\\Player\\\mods\", @"C:\USERS\PLAYER\MODS")]
    [InlineData(@"C:\Users\Player\.\mods\..\config", @"C:\USERS\PLAYER\CONFIG")]
    [InlineData(@"C:\..\..\Windows", @"C:\WINDOWS")]
    [InlineData(@"C:", @"C:\")]
    [InlineData(@"C:\", @"C:\")]
    [InlineData(@"C:\mods\client.jar.", @"C:\MODS\CLIENT.JAR")]
    [InlineData(@"C:\mods\client.jar ", @"C:\MODS\CLIENT.JAR")]
    [InlineData(@"C:\Пользователи\Игрок\моды", @"C:\ПОЛЬЗОВАТЕЛИ\ИГРОК\МОДЫ")]
    [InlineData(@"C:\a\...\b", @"C:\A\...\B")]
    public void Normalizes_to_comparison_form(string input, string expected)
    {
        Assert.Equal(expected, PathNormalizer.Normalize(input));
    }

    [Theory]
    [InlineData((string?)null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_input_gives_null(string? input)
    {
        Assert.Null(PathNormalizer.Normalize(input));
    }

    [Fact]
    public void Device_and_volume_paths_are_mapped_through_the_volume_map()
    {
        var map = new VolumeMap();
        map.Add(@"\Device\HarddiskVolume3", "c:");
        map.Add(@"\VOLUME{01d9a0b1c2d3e4f5-a1b2c3d4}", "D:");

        Assert.Equal(@"C:\USERS\P\JAVAW.EXE", PathNormalizer.Normalize(@"\DEVICE\HARDDISKVOLUME3\Users\p\javaw.exe", map));
        Assert.Equal(@"D:\GAMES\X.JAR", PathNormalizer.Normalize(@"\VOLUME{01d9a0b1c2d3e4f5-a1b2c3d4}\Games\x.jar", map));
        Assert.Equal(@"C:\", PathNormalizer.Normalize(@"\Device\HarddiskVolume3", map));
    }

    [Fact]
    public void Volume_map_does_not_match_a_longer_volume_number()
    {
        var map = new VolumeMap();
        map.Add(@"\Device\HarddiskVolume3", "C:");
        Assert.Equal(@"\DEVICE\HARDDISKVOLUME30\X", PathNormalizer.Normalize(@"\Device\HarddiskVolume30\x", map));
    }

    [Fact]
    public void Unmapped_device_paths_stay_distinct_rather_than_guessed()
    {
        Assert.Equal(@"\DEVICE\HARDDISKVOLUME3\USERS\P", PathNormalizer.Normalize(@"\Device\HarddiskVolume3\Users\p"));
    }

    [Theory]
    [InlineData("C")]
    [InlineData("CC:")]
    [InlineData("1:")]
    public void Volume_map_rejects_invalid_drive_letters(string drive)
    {
        Assert.Throws<ArgumentException>(() => new VolumeMap().Add(@"\Device\HarddiskVolume1", drive));
    }

    [Theory]
    [InlineData(@"C:\mods\Client.JAR", "CLIENT.JAR")]
    [InlineData(@"C:\mods\", "MODS")]
    [InlineData(@"C:\", null)]
    [InlineData(@"client.jar", "CLIENT.JAR")]
    public void File_name_is_the_last_component(string path, string? expected)
    {
        Assert.Equal(expected, PathNormalizer.FileName(path));
    }

    [Theory]
    [InlineData(@"C:\Users\p\.minecraft\mods\x.jar", @"c:\users\P\.minecraft", true)]
    [InlineData(@"C:\Users\p\.minecraft", @"C:\Users\p\.minecraft\", true)]
    [InlineData(@"C:\Users\p\.minecraft-old\x.jar", @"C:\Users\p\.minecraft", false)]
    [InlineData(@"D:\Users\p\.minecraft\x.jar", @"C:\Users\p\.minecraft", false)]
    public void Under_folder_respects_component_boundaries(string path, string folder, bool expected)
    {
        Assert.Equal(expected, PathNormalizer.IsUnder(path, folder));
    }
}
