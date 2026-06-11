Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c C:\zai\zair\target\release\zair.exe agent > C:\zai\zair\run.log 2>&1", 0, False
