Set WshShell = CreateObject("WScript.Shell")
WshShell.Environment("Process").Item("RUST_LOG") = "zair=info"
WshShell.CurrentDirectory = "C:\zai\zair"
WshShell.Run "cmd /c C:\zai\zair\target\release\zair.exe agent --name ""ZAI Agent"" --server https://aicq.online --model glm-4-plus > C:\zai\zair\zair.log 2>&1", 0, False
