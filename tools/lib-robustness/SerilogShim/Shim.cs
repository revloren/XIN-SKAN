// Minimal stand-in for Serilog so the libraries compile offline. Logging is a no-op;
// it does not change parsing behaviour. Messages are counted so the harness can report them.
using System;
namespace Serilog.Events { public enum LogEventLevel { Verbose, Debug, Information, Warning, Error, Fatal } }
namespace Serilog
{
    public static class Log
    {
        public static int Warnings, Errors;
        public static bool IsEnabled(Serilog.Events.LogEventLevel l) => false;
        public static void Verbose(string m, params object[] a) { }
        public static void Verbose(Exception e, string m, params object[] a) { }
        public static void Debug(string m, params object[] a) { }
        public static void Debug(Exception e, string m, params object[] a) { }
        public static void Information(string m, params object[] a) { }
        public static void Information(Exception e, string m, params object[] a) { }
        public static void Warning(string m, params object[] a) { Warnings++; }
        public static void Warning(Exception e, string m, params object[] a) { Warnings++; }
        public static void Error(string m, params object[] a) { Errors++; }
        public static void Error(Exception e, string m, params object[] a) { Errors++; }
    }
}
