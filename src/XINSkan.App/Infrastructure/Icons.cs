using System.Windows;
using System.Windows.Media;

namespace XINSkan.App.Infrastructure;

/// <summary>Line icons on a 24×24 grid, drawn as strokes so the glass tile shows through them.</summary>
public static class Icons
{
    public static Geometry Dashboard { get; } = Freeze(Geometry.Parse("M3.5,3.5 H10.5 V10.5 H3.5 Z M13.5,3.5 H20.5 V10.5 H13.5 Z M3.5,13.5 H10.5 V20.5 H3.5 Z M13.5,13.5 H20.5 V20.5 H13.5 Z"));

    public static Geometry Investigation { get; } = Freeze(new GeometryGroup
    {
        Children =
        {
            new EllipseGeometry(new Point(10, 10), 6.5, 6.5),
            new LineGeometry(new Point(14.8, 14.8), new Point(20.5, 20.5)),
        },
    });

    public static Geometry Timeline { get; } = Freeze(new GeometryGroup
    {
        Children =
        {
            Geometry.Parse("M12,2.5 V21.5"),
            new EllipseGeometry(new Point(12, 6), 2, 2),
            new EllipseGeometry(new Point(12, 13), 2, 2),
            new EllipseGeometry(new Point(12, 19.5), 1.4, 1.4),
            Geometry.Parse("M14,6 H20.5 M4,13 H10 M14,19.5 H18"),
        },
    });

    public static Geometry Reports { get; } = Freeze(Geometry.Parse("M6,2.5 H14 L19,7.5 V21.5 H6 Z M14,2.5 V7.5 H19 M9,12.5 H16 M9,16.5 H14"));

    public static Geometry Database { get; } = Freeze(Geometry.Parse("M4.5,6 A7.5,3 0 1 0 19.5,6 A7.5,3 0 1 0 4.5,6 Z M4.5,6 V18 A7.5,3 0 0 0 19.5,18 V6 M4.5,12 A7.5,3 0 0 0 19.5,12"));

    public static Geometry Network { get; } = Freeze(new GeometryGroup
    {
        Children =
        {
            new EllipseGeometry(new Point(12, 5), 2.4, 2.4),
            new EllipseGeometry(new Point(5, 18.5), 2.4, 2.4),
            new EllipseGeometry(new Point(19, 18.5), 2.4, 2.4),
            Geometry.Parse("M10.8,7.1 L6.2,16.4 M13.2,7.1 L17.8,16.4 M7.4,18.5 H16.6"),
        },
    });

    public static Geometry Settings { get; } = Freeze(new GeometryGroup
    {
        Children =
        {
            Geometry.Parse("M3.5,7 H20.5 M3.5,17 H20.5"),
            new EllipseGeometry(new Point(9, 7), 2.6, 2.6),
            new EllipseGeometry(new Point(15.5, 17), 2.6, 2.6),
        },
    });

    private static Geometry Freeze(Geometry g)
    {
        if (!g.IsFrozen)
        {
            g.Freeze();
        }

        return g;
    }
}
