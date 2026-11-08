using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Xunit.Abstractions;
using XINSkan.App.ViewModels;

namespace XINSkan.AppTests;

/// <summary>
/// Opens the real main window, visits every screen, and fails on any WPF data-binding error. Each screen is
/// rendered to PNG and written to the test log in chunks (marker "XINSKAN-SHOT") for visual review.
/// </summary>
public sealed class VisualSmokeTests(ITestOutputHelper output)
{
    private sealed class BindingErrors : TraceListener
    {
        public List<string> Messages { get; } = [];

        public override void Write(string? message)
        {
        }

        public override void WriteLine(string? message)
        {
            if (message is not null)
            {
                Messages.Add(message);
            }
        }
    }

    [Fact]
    public void Every_screen_renders_without_binding_errors()
    {
        Exception? failure = null;
        var errors = new BindingErrors();
        var shots = new List<(string Name, byte[] Png)>();

        var thread = new Thread(() =>
        {
            try
            {
                PresentationTraceSources.Refresh();
                PresentationTraceSources.DataBindingSource.Listeners.Add(errors);
                PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning;

                var app = new XINSkan.App.App();
                app.InitializeComponent();

                var window = new XINSkan.App.MainWindow
                {
                    Width = 1280,
                    Height = 800,
                    WindowStartupLocation = WindowStartupLocation.Manual,
                    Left = 0,
                    Top = 0,
                    ShowActivated = false,
                };
                window.Show();
                var vm = (MainViewModel)window.DataContext;

                for (var i = 0; i < vm.Items.Count; i++)
                {
                    vm.Navigate(i);
                    Pump(TimeSpan.FromSeconds(i == 0 ? 4 : 2));
                    shots.Add(($"{i}-{vm.Items[i].Title}", Render(window)));
                }

                window.Close();
                app.Shutdown();
            }
#pragma warning disable CA1031 // The exception is rethrown on the test thread.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromMinutes(2)), "The window did not finish rendering in 2 minutes.");
        Assert.Null(failure);

        foreach (var (name, png) in shots)
        {
            var b64 = Convert.ToBase64String(png);
            const int chunk = 6000;
            var parts = (b64.Length + chunk - 1) / chunk;
            for (var p = 0; p < parts; p++)
            {
                output.WriteLine($"XINSKAN-SHOT {name.Replace(' ', '_')} {p + 1}/{parts} {b64.Substring(p * chunk, Math.Min(chunk, b64.Length - (p * chunk)))}");
            }
        }

        Assert.Equal(7, shots.Count);
        Assert.All(shots, s => Assert.True(s.Png.Length > 10_000, $"{s.Name} rendered almost nothing."));
        Assert.Empty(errors.Messages);
    }

    private static void Pump(TimeSpan duration)
    {
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = duration };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            frame.Continue = false;
        };
        timer.Start();
        Dispatcher.PushFrame(frame);
    }

    private static byte[] Render(Window window)
    {
        var root = (FrameworkElement)window.Content;
        root.UpdateLayout();
        var width = Math.Max(1, (int)Math.Ceiling(root.ActualWidth));
        var height = Math.Max(1, (int)Math.Ceiling(root.ActualHeight));

        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        var background = new DrawingVisual();
        using (var dc = background.RenderOpen())
        {
            dc.DrawRectangle(window.Background, null, new Rect(0, 0, width, height));
        }

        bitmap.Render(background);
        bitmap.Render(root);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }
}
