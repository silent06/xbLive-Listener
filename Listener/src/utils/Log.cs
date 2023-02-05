using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Listener {
    class Log {
        public struct PrintQueue {
            public ConsoleColor Color;
            public string Message;
            public string Spec;
            public string IP;
        }

        private static bool bBusy;

        public static List<PrintQueue> GetQueue() {
            return new List<PrintQueue>();
        }

        public static void Add(List<PrintQueue> queue, ConsoleColor color, string spec, string message, string ip) {
            PrintQueue data;
            data.Color = color;
            data.Message = message;
            data.Spec = spec;
            data.IP = ip;
            queue.Add(data);
        }

        public static void Print(List<PrintQueue> queue) {
            new Thread(() => {
                while (!Print2(queue)) {
                    Thread.Sleep(1000);
                }
            }).Start();
        }

        public static bool Print2(List<PrintQueue> queue) {
            if (bBusy) {
                return false;
            } else {
                bBusy = true;
                string endIp = "[" + queue[0].IP + "]";
                string time = "[" + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss") + "]";

                int count = 0;
                foreach (var e in queue) {
                    int c = time.Length + e.Spec.Length + endIp.Length + 2;
                    if (c > count) {
                        count = c;
                    }
                }

                foreach (var e in queue) {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write(time + " ");

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write(endIp + " ");

                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(e.Spec + " ");

                    for (int i = 0; i < count - e.Spec.Length - time.Length - endIp.Length - 1; i++) Console.Write(" ");

                    Console.ForegroundColor = e.Color;
                    Console.Write(e.Message + Environment.NewLine);
                }

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("");

                bBusy = false;
                return true;
            }
        }
    }
}
