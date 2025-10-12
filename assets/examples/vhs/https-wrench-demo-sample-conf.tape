
Output https-wrench-demo-sample-conf.gif
#Output https-wrench-demo-sample-conf.mp4
#Output https-wrench-demo-sample-conf.webm

Require echo
Require https-wrench

Set Shell "bash"
Set FontSize 20
Set FontFamily Hack
Set Theme catppuccin-frappe
Set Width 1500
Set Height 2000

Type "https-wrench -h" Sleep 500ms  Enter
Type "https-wrench --show-sample-config > sample-wrench.yaml" Sleep 500ms  Enter
Ctrl+l
Type "https-wrench --config sample-wrench.yaml requests" Enter

Sleep 5s
