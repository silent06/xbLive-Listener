using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Listener {
    class MetricProcessor {
        public static void ProcessMetrics(string console_key) {
            List<ClientMetric> metrics = MySQL.GetClientMetrics(console_key);
            if (metrics.Count > 0) {
                int warningCount = 0;
                foreach (var metric in metrics) {
                    if (metric.Type == eMetricType.METRIC_DISABLE_ACCOUNT) {
                        MySQL.BanClient(console_key, "Account disabled for suspicious activity");
                        Console.WriteLine("Banned {0} for receiving a bannable metric", console_key);
                        break;
                    }

                    if (metric.Type == eMetricType.METRIC_WARNING) {
                        warningCount++;
                    }
                }

                if (warningCount >= 5) {
                    MySQL.BanClient(console_key, "Account disabled for suspicious activity");
                    Console.WriteLine("Banned {0} for receiving 5 warning metrics", console_key);
                }
            }
        }
    }
}
