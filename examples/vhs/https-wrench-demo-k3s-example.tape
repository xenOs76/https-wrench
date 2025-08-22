
Output https-wrench-demo-k3s-example.gif
#Output https-wrench-demo-k3s-example.mp4
#Output https-wrench-demo-k3s-example.webm

Require echo
Require https-wrench

Set Shell "bash"
Set FontSize 20
Set FontFamily Hack
Set Theme catppuccin-frappe
Set Width 1500
Set Height 1500

Type "https-wrench --config https-wrench-k3s.yaml requests" Enter

Sleep 5s
