using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FileServerMonitor.Data;
using FileServerMonitor.Services;
using Microsoft.EntityFrameworkCore;


class Program
{
    //// === WinAPI stuff ===
    //const int SC_CLOSE = 0xF060;
    //const int MF_GRAYED = 0x00000001;
    //const int SW_HIDE = 0;

    //[DllImport("kernel32.dll")]
    //private static extern IntPtr GetConsoleWindow();

    //[DllImport("user32.dll")]
    //private static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

    //[DllImport("user32.dll")]
    //private static extern bool EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable);

    //[DllImport("user32.dll")]
    //private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    //static void DisableCloseButton()
    //{
    //    IntPtr hWnd = GetConsoleWindow();
    //    IntPtr hMenu = GetSystemMenu(hWnd, false);

    //    if (hMenu != IntPtr.Zero)
    //    {
    //        EnableMenuItem(hMenu, SC_CLOSE, MF_GRAYED); // Disable X button
    //    }
    //}

    //static void HideConsole()
    //{
    //    IntPtr hWnd = GetConsoleWindow();
    //    ShowWindow(hWnd, SW_HIDE); // Hide console window
    //}

    public static void Main(string[] args)
    {
        //// Prevent closing via "X"
        //DisableCloseButton();

        //// Hide the console window (comment out if you want to see logs)
        //HideConsole();

        var builder = WebApplication.CreateBuilder(args);

        // Use HTTP on port 80
        builder.WebHost.UseUrls("http://0.0.0.0:80");

        // Add DbContext for SQL Server
        builder.Services.AddDbContext<AppDbContext>(opt =>
            opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

        // Add controllers
        builder.Services.AddControllers();

        // Add monitoring service
        builder.Services.AddHostedService<FileSystemWatcherService>();

        var app = builder.Build();

        // === Basic Authentication Middleware ===
        var username = "administrator";   // 🔐 change this
        var password = "Admin2@25";   // 🔐 change this

        app.Use(async (context, next) =>
        {
            string authHeader = context.Request.Headers["Authorization"];

            if (authHeader != null && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var token = authHeader.Substring("Basic ".Length).Trim();
                var credentialString = Encoding.UTF8.GetString(Convert.FromBase64String(token));
                var credentials = credentialString.Split(':', 2);

                if (credentials.Length == 2 &&
                    credentials[0] == username &&
                    credentials[1] == password)
                {
                    await next(); // Auth success → continue
                    return;
                }
            }

            // If not authenticated → return 401 with popup
            context.Response.StatusCode = 401;
            context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"FileServerMonitor\"";
        });

        // Development tools
        app.UseDeveloperExceptionPage();

        // Serve static files
        app.UseDefaultFiles();
        app.UseStaticFiles();

        // Map API controllers
        app.MapControllers();

        // Run app
        app.Run();
    }
}
