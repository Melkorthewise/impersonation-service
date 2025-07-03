Imports System.Runtime.InteropServices
Imports System.Security.Principal
Imports Microsoft.Win32

Imports System.IO
Imports System.ServiceProcess
Imports System.Threading.Tasks
Imports System.ComponentModel.Design
Imports System.Threading
Imports System.CodeDom
Imports Microsoft.VisualBasic.Devices
Imports System.Runtime.CompilerServices
Imports System.Management

Public Class Service2
    Inherits ServiceBase

    Private _log As Logger
    Private _impersonater As UserImpersonator

    Protected Overrides Sub OnStart(ByVal args() As String)
        _log = New Logger()
        _impersonater = New UserImpersonator(_log)

        _log.write2log("Service started")

        ' Run impersonation asynchronously to avoid blocking OnStart
        Task.Run(Sub()
                     _impersonater.ImpersonateActiveUser()
                 End Sub)
    End Sub

    Protected Overrides Sub OnStop()
        _log.write2log("Service stopped")
    End Sub
End Class

Public Class UserImpersonator
    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function DuplicateTokenEx(
        hExistingToken As IntPtr,
        dwDesiredAccess As UInteger,
        lpTokenAttributes As IntPtr,
        impersonationLevel As Integer,
        tokenType As Integer,
        ByRef phNewToken As IntPtr) As Boolean
    End Function

    Private Const TOKEN_ALL_ACCESS As UInteger = &H10000000
    Private Const SecurityImpersonation As Integer = 2
    Private Const TokenPrimary As Integer = 1

    <DllImport("wtsapi32.dll", SetLastError:=True)>
    Private Shared Function WTSQueryUserToken(sessionId As UInteger, ByRef token As IntPtr) As Boolean
    End Function

    <DllImport("kernel32.dll", SetLastError:=True)>
    Private Shared Function CloseHandle(hObject As IntPtr) As Boolean
    End Function

    <DllImport("kernel32.dll")>
    Private Shared Function WTSGetActiveConsoleSessionId() As UInteger
    End Function

    <DllImport("userenv.dll", SetLastError:=True, CharSet:=CharSet.Auto)>
    Private Shared Function LoadUserProfile(hToken As IntPtr, ByRef lpProfileInfo As PROFILEINFO) As Boolean
    End Function

    <DllImport("userenv.dll", SetLastError:=True)>
    Private Shared Function UnloadUserProfile(hToken As IntPtr, hProfile As IntPtr) As Boolean
    End Function

    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Auto)>
    Public Structure PROFILEINFO
        Public dwSize As Integer
        Public dwFlags As Integer
        <MarshalAs(UnmanagedType.LPTStr)> Public lpUserName As String
        <MarshalAs(UnmanagedType.LPTStr)> Public lpProfilePath As String
        <MarshalAs(UnmanagedType.LPTStr)> Public lpDefaultPath As String
        <MarshalAs(UnmanagedType.LPTStr)> Public lpServerName As String
        <MarshalAs(UnmanagedType.LPTStr)> Public lpPolicyPath As String
        Public hProfile As IntPtr
    End Structure

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function OpenProcessToken(
    ByVal processHandle As IntPtr,
    ByVal desiredAccess As UInteger,
    ByRef tokenHandle As IntPtr) As Boolean
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function LookupPrivilegeValue(
    ByVal lpSystemName As String,
    ByVal lpName As String,
    ByRef lpLuid As LUID) As Boolean
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function AdjustTokenPrivileges(
    ByVal tokenHandle As IntPtr,
    ByVal disableAllPrivileges As Boolean,
    ByRef newState As TOKEN_PRIVILEGES,
    ByVal bufferLength As Integer,
    ByVal previousState As IntPtr,
    ByVal returnLength As IntPtr) As Boolean
    End Function

    <StructLayout(LayoutKind.Sequential)>
    Private Structure LUID
        Public LowPart As UInteger
        Public HighPart As Integer
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Private Structure TOKEN_PRIVILEGES
        Public PrivilegeCount As UInteger
        Public Luid As LUID
        Public Attributes As UInteger
    End Structure

    Private Const TOKEN_ADJUST_PRIVILEGES As UInteger = &H20
    Private Const TOKEN_QUERY As UInteger = &H8
    Private Const SE_PRIVILEGE_ENABLED As UInteger = &H2


    Private ReadOnly _log As Logger

    Public Sub New(log As Logger)
        _log = log
    End Sub

    Public Sub ImpersonateActiveUser()
        _log.write2log("Before impersonation: " & WindowsIdentity.GetCurrent().Name)

        Dim sessionId = WTSGetActiveConsoleSessionId()
        Dim userToken As IntPtr = IntPtr.Zero

        If WTSQueryUserToken(sessionId, userToken) Then
            Dim primaryToken As IntPtr = IntPtr.Zero

            If Not DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, primaryToken) Then
                _log.write2log("DuplicateTokenEx failed. Error " & Marshal.GetLastWin32Error())
                Dim err = Marshal.GetLastWin32Error()
                _log.write2log("Failed to duplicate token. Error: " & err)
                CloseHandle(userToken)
                Return
            End If

            ' Close the original impersonation token
            CloseHandle(userToken)
            userToken = primaryToken

            Try
                ' Grant SYSTEM the needed privileges BEFORE impersonating
                EnablePrivilegeOnCurrentProcess("SeBackupPrivilege")
                EnablePrivilegeOnCurrentProcess("SeRestorePrivilege")

                Using identity = New WindowsIdentity(userToken)
                    _log.write2log("Identity.Name = " & identity.Name)

                    '' Prepare PROFILEINFO for LoadUserProfile
                    Dim profileInfo As New PROFILEINFO()
                    profileInfo.dwSize = Marshal.SizeOf(GetType(PROFILEINFO))
                    profileInfo.dwFlags = 1 ' PI_NOUI
                    profileInfo.lpProfilePath = Nothing
                    profileInfo.lpDefaultPath = Nothing
                    profileInfo.lpServerName = Nothing
                    profileInfo.lpPolicyPath = Nothing

                    Dim userParts = identity.Name.Split("\"c)
                    If userParts.Length = 2 Then
                        profileInfo.lpUserName = userParts(1)
                    Else
                        profileInfo.lpUserName = identity.Name
                    End If

                    profileInfo.hProfile = IntPtr.Zero

                    _log.write2log("PROFILEINFO.dwSize: " & profileInfo.dwSize)
                    _log.write2log("PROFILEINFO.lpUserName: " & profileInfo.lpUserName)
                    _log.write2log("User token is valid: " & (userToken <> IntPtr.Zero))

                    WriteRegistryValue(identity)

                    ' Load profile while still running as SYSTEM
                    If Not LoadUserProfile(userToken, profileInfo) Then
                        Dim err = Marshal.GetLastWin32Error()
                        _log.write2log("Failed to load user profile, error: " & err)
                    Else
                        _log.write2log("Profile loaded successfully. hProfile: " & profileInfo.hProfile.ToInt64())

                        ' Now impersonate
                        Using impersonationContext = identity.Impersonate()
                            _log.write2log("Impersonation successful!")
                            _log.write2log("After Impersonation: " & WindowsIdentity.GetCurrent().Name)

                            Try
                                ' Do whatever under impersonation
                                'WriteRegistryValue(identity)
                            Catch ex As Exception
                                _log.write2log("Registry write threw: " & ex.Message)
                            End Try
                        End Using

                        ' Unload profile when done
                        If Not UnloadUserProfile(userToken, profileInfo.hProfile) Then
                            Dim unloadErr = Marshal.GetLastWin32Error()
                            _log.write2log("Failed to unload user profile, error: " & unloadErr)
                        End If
                    End If
                End Using
            Catch ex As Exception
                _log.write2log("Error during impersonation: " & ex.Message)
            Finally
                CloseHandle(userToken)
            End Try
        Else
            Dim errorCode = Marshal.GetLastWin32Error()
            _log.write2log($"Failed to get user token. Error code: {errorCode}")
        End If
    End Sub

    ' HKEY_CURRENT_USER != impersonated user when running as a system.
    Sub WriteRegistryValue(identity As WindowsIdentity)
        ' Assume impersonation is active here

        Dim path = "Software\TestKey"

        Try
            Using key = Registry.CurrentUser.CreateSubKey("Software\TestKey")
                key.SetValue("1", "dummy.exe")
                _log.write2log("Registry write successful to HKCU.")
            End Using
        Catch ex As Exception
            _log.write2log("Registry write threw: " & ex.Message)
        End Try
    End Sub

    Private Sub EnablePrivilegeOnCurrentProcess(privilegeName As String)
        Dim tokenHandle As IntPtr
        If OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES Or TOKEN_QUERY, tokenHandle) Then
            Dim luid As New LUID()
            If LookupPrivilegeValue(Nothing, privilegeName, luid) Then
                Dim tp As New TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Luid = luid
                tp.Attributes = SE_PRIVILEGE_ENABLED

                Dim result = AdjustTokenPrivileges(tokenHandle, False, tp, 0, IntPtr.Zero, IntPtr.Zero)
                Dim err = Marshal.GetLastWin32Error()
                If result AndAlso err = 0 Then
                    _log.write2log($"Privilege {privilegeName} enabled successfully on process token.")
                Else
                    _log.write2log($"Failed to enable privilege {privilegeName} on process token. Error: {err}")
                End If
            Else
                _log.write2log($"LookupPrivilegeValue failed for {privilegeName}.")
            End If
            CloseHandle(tokenHandle)
        Else
            _log.write2log("OpenProcessToken failed in EnablePrivilegeOnCurrentProcess.")
        End If
    End Sub

End Class


Public Class Logger
    Private ReadOnly pad As String = "C:\Users\Public\Service"

    Public Sub write2log(waarde As String)
        If Not Directory.Exists(pad + "\Logs") Then
            Directory.CreateDirectory(pad + "\Logs")
        End If

        Try
            File.AppendAllText(pad + "\Logs\Service_log.txt", Now.ToString + vbTab + waarde & vbCrLf)
        Catch ex As Exception
            Exit Sub
        End Try
    End Sub
End Class
