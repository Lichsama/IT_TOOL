using MahApps.Metro.Controls;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.Devices;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;


namespace WPFAPP_DENEME
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : MetroWindow
    {
        private DispatcherTimer uptimeTimer;
        public MainWindow()
        {
            InitializeComponent();
            LoadSystemInfo();
           
        }

        [DllImport("kernel32.dll")]
        static extern ulong GetTickCount64();

        private void LoadSystemInfo()
        {
            string user = Environment.UserName;
            string pc = Environment.MachineName;
            string os = Environment.OSVersion.ToString();
            string cpu = GetCpuName();
            string gpu = GetGpuName();
            string ip = GetLocalIP();
            string ram = $"{Math.Round((double)new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory / 1024 / 1024 / 1024, 1)} GB";
            ulong uptimeMillis = GetTickCount64();
            TimeSpan uptime = TimeSpan.FromMilliseconds(uptimeMillis);



            txtSystemInfo.Text = $"User: {user}\nComputer Name: {pc}\nOS: {os}\nCPU: {cpu}\nGPU: {gpu}\nRAM: {ram}\nIP Address: {ip}";

            txtSystemStatus.Text = $"CPU Usage: {GetCpuUsage()}%\n" +
                                   $"Memory Usage: {GetRamUsage()}%\n" +
                                   $"Disk Usage: C: {GetDiskUsage()} used\n" +
                                   $"Network: {GetNetworkSpeed()}\n"+
                                   $"System Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m"; ;
        }

        private string GetCpuName()
        {
            var searcher = new ManagementObjectSearcher("select Name from Win32_Processor");
            foreach (var item in searcher.Get())
                return item["Name"].ToString();
            return "Unknown CPU";
        }

        private string GetGpuName()
        {
            var searcher = new ManagementObjectSearcher("select Name from Win32_VideoController");
            foreach (var item in searcher.Get())
                return item["Name"].ToString();
            return "Unknown GPU";
        }

        private string GetLocalIP()
        {
            string ip = "Unknown";
            foreach (var addr in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    ip = addr.ToString();
                    break;
                }
            }
            return ip;
        }

        private int GetCpuUsage()
        {
            var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            cpuCounter.NextValue();
            System.Threading.Thread.Sleep(1000);
            return (int)cpuCounter.NextValue();
        }

        private int GetRamUsage()
        {
            var info = new Microsoft.VisualBasic.Devices.ComputerInfo();
            ulong total = info.TotalPhysicalMemory;
            ulong available = info.AvailablePhysicalMemory;
            double used = ((double)(total - available) / total) * 100;
            return (int)used;
        }

        private string GetDiskUsage()
        {
            var cDrive = new DriveInfo("C");
            double percentUsed = (double)(cDrive.TotalSize - cDrive.TotalFreeSpace) / cDrive.TotalSize * 100;
            return $"{percentUsed:F2}%";
        }

        private string GetNetworkSpeed()
        {
            // Basit placeholder, istersen gerçek hız ölçümü ekleriz sonra
            return "1.5KB/s in | 0KB/s out";
        }

        private void ChangeHostname_Click(object sender, RoutedEventArgs e)
        {
            string currentHostname = Environment.MachineName;
            string newHostname = Interaction.InputBox("Enter new hostname:", "Change Hostname", currentHostname);

            if (!string.IsNullOrWhiteSpace(newHostname) && newHostname != currentHostname)
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"Rename-Computer -NewName \"{newHostname}\" -Force -PassThru",
                        Verb = "runas",
                        UseShellExecute = true
                    });
                    txtActivityLog.Text += $"[{DateTime.Now:T}] Hostname changed from '{currentHostname}' to '{newHostname}' (restart required)\n";
                }
                catch
                {
                    txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to change hostname.\n";
                }
            }
        }


        private void ChangeDescription_Click(object sender, RoutedEventArgs e)
        {
            string currentDescription = "";
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"))
                {
                    if (key != null)
                        currentDescription = key.GetValue("srvcomment")?.ToString() ?? "";
                }
            }
            catch { currentDescription = ""; }

            string newDescription = Interaction.InputBox("Enter new computer description:", "Change Description", currentDescription);

            if (!string.IsNullOrWhiteSpace(newDescription) && newDescription != currentDescription)
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name srvcomment -Value \"{newDescription}\"",
                        Verb = "runas",
                        UseShellExecute = true
                    });
                    txtActivityLog.Text += $"[{DateTime.Now:T}] Description changed from '{currentDescription}' to '{newDescription}'\n";
                }
                catch
                {
                    txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to change description.\n";
                }
            }
        }

        private void RunSfcScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string taskName = "RunSfcScanViaToolkit";

                // Görevi oluştur (cmd /k ile pencere açık kalacak)
                Process.Start(new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/Create /TN \"{taskName}\" /TR \"cmd.exe /k sfc /scannow\" /SC ONCE /ST 00:00 /RL HIGHEST /F",
                    Verb = "runas",
                    UseShellExecute = true
                })?.WaitForExit();

                // Görevi hemen çalıştır
                Process.Start(new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/Run /TN \"{taskName}\"",
                    Verb = "runas",
                    UseShellExecute = true
                });

                txtActivityLog.Text += $"[{DateTime.Now:T}] SFC scan triggered via scheduled task (with visible CMD).\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to trigger SFC scan: {ex.Message}\n";
            }
        }







        private void RunDismRepair_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "DISM /Online /Cleanup-Image /RestoreHealth",
                    Verb = "runas",
                    UseShellExecute = true
                });

                txtActivityLog.Text += $"[{DateTime.Now:T}] DISM repair started.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to start DISM repair: {ex.Message}\n";
            }
        }

        private void FlushDns_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c ipconfig /flushdns",
                    Verb = "runas",
                    UseShellExecute = true
                });
                txtActivityLog.Text += $"[{DateTime.Now:T}] DNS flushed successfully.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to flush DNS: {ex.Message}\n";
            }
        }

        private void NetworkReset_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/k netsh winsock reset && netsh int ip reset",
                    Verb = "runas",
                    UseShellExecute = true
                });
                txtActivityLog.Text += $"[{DateTime.Now:T}] Network reset commands triggered.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to reset network: {ex.Message}\n";
            }
        }
        private void RestartExplorer_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c taskkill /f /im explorer.exe && start explorer.exe",
                    Verb = "runas",
                    UseShellExecute = true
                });
                txtActivityLog.Text += $"[{DateTime.Now:T}] Windows Explorer restarted.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to restart Explorer: {ex.Message}\n";
            }
        }
        private void ResetWindowsUpdate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string script = "net stop wuauserv & net stop bits & net stop cryptsvc & " +
                                "ren C:\\Windows\\SoftwareDistribution SoftwareDistribution.bak & " +
                                "ren C:\\Windows\\System32\\catroot2 catroot2.bak & " +
                                "net start wuauserv & net start bits & net start cryptsvc";

                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/k {script}",
                    Verb = "runas",
                    UseShellExecute = true
                });

                txtActivityLog.Text += $"[{DateTime.Now:T}] Windows Update components reset triggered.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to reset Windows Update: {ex.Message}\n";
            }
        }
        private void ClearUserTemp_Click(object sender, RoutedEventArgs e)
        {
            string userTemp = Environment.ExpandEnvironmentVariables("%TEMP%");

            try
            {
                foreach (var file in Directory.GetFiles(userTemp))
                {
                    try { File.Delete(file); }
                    catch { /* dosya kullanımda olabilir, geç */ }
                }

                foreach (var dir in Directory.GetDirectories(userTemp))
                {
                    try { Directory.Delete(dir, true); }
                    catch { /* klasör kullanımda olabilir, geç */ }
                }

                txtActivityLog.Text = "User TEMP folder cleaned.";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text = "Error cleaning user TEMP: " + ex.Message;
            }
        }

        private void ClearWindowsTemp_Click(object sender, RoutedEventArgs e)
        {
            string windowsTemp = @"C:\Windows\Temp";

            try
            {
                foreach (var file in Directory.GetFiles(windowsTemp))
                {
                    try { File.Delete(file); }
                    catch { /* erişim hatası varsa atla */ }
                }

                foreach (var dir in Directory.GetDirectories(windowsTemp))
                {
                    try { Directory.Delete(dir, true); }
                    catch { /* erişim hatası varsa atla */ }
                }

                txtActivityLog.Text = "Windows TEMP folder cleaned.";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text = "Error cleaning Windows TEMP: " + ex.Message;
            }
        }

        private void RunTrim_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c defrag C: /L",
                Verb = "runas",
                CreateNoWindow = true
            });
            Log("TRIM (defrag /L) initiated on C: drive.");
        }
        private void RunChkdsk_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c chkdsk C: /f /r",
                Verb = "runas"
            });
            Log("CHKDSK /F /R started on C: drive.");
        }
        private void Log(string message)
        {
            txtActivityLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            txtActivityLog.ScrollToEnd();
        }
        private void Outlook2016_2019_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c REG ADD HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\AutoDiscover /v ExcludeExplicitO365Endpoint /t REG_DWORD /D 1 /f",
                    Verb = "runas",
                    UseShellExecute = true
                });

                txtActivityLog.Text += $"[{DateTime.Now:T}] Applied Outlook 2016-2019 registry fix.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to apply fix: {ex.Message}\n";
            }
        }
        private void Outlook2021_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string psCommand = @"
New-Item -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook -Name AutoDiscover -Force;
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover' -Name DisableAutodiscoverV2Service -Type DWord -Value 1";

                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{psCommand}\"",
                    Verb = "runas",
                    UseShellExecute = true
                });

                txtActivityLog.Text += $"[{DateTime.Now:T}] Applied Outlook 2021 registry fix.\n";
            }
            catch (Exception ex)
            {
                txtActivityLog.Text += $"[{DateTime.Now:T}] Failed to apply fix: {ex.Message}\n";
            }
        }
        private void EnableUltimatePerformance_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61",
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(psi);

                txtActivityLog.AppendText($"[{DateTime.Now:HH:mm:ss}] Ultimate Performance plan enabled.\n");
                txtActivityLog.ScrollToEnd();
            }
            catch (Exception ex)
            {
                txtActivityLog.AppendText($"[{DateTime.Now:HH:mm:ss}] Failed to enable performance plan: {ex.Message}\n");
                txtActivityLog.ScrollToEnd();
            }
        }

        private void StartUptimeTimer()
        {
            uptimeTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            uptimeTimer.Tick += UpdateUptime;
            uptimeTimer.Start();
        }

        private void UpdateUptime(object sender, EventArgs e)
        {
            TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount);
            txtSystemStatus.Text = $"System Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m {uptime.Seconds}s";
        }
    }
}
