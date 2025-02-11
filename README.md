# CPSC_455_Project
# Fall 2024, CPSC 455, Section 1

# Project 4

## 1. Clone the Repository and Run the Code

We cloned the repository and ran the code with the following commands:

```
$ git clone https://github.com/ProfAvery/cpsc455-project3.git
$ cd cpsc455-project
$ cp .env_default .env
$ npm install
$ npm start
```
## 2. SQLMAP

After reviewing the sqlmap documentation, it was determined that a --url='<URL>' option could be
supplied as a switch when executing sqlmap. The link
[http://keillormint-22:8080/?page=history&hostname=www.google.com](http://keillormint-22:8080/?page=history&hostname=www.google.com) was provided, as the source code
indicates that the hostname variable is vulnerable.

We quickly gain a bunch of information, but most notably that sqlmap recognizes that this is both sqlite
and Express.


While the API endpoints are not secure, they do not allow for the data to be returned directly to
the client (which is a good thing). This makes it a little more difficult to exploit the program using
sqlmap. After taking a quick look at the source code, we can see that the comments POST route is
vulnerable to sql injection, but sqlmap has a difficult time detecting this. sqlmap does not detect this
vulnerability automatically.

When attempting to access the OS shell using sqlmap, an error occurred because SQLite does not support
that type of command usage.


#### Sqlmap also indicates that the /ping endpoint is not exploitable, a conclusion that aligns with our

#### observations. You would need to craft a command that is valid appended onto the end of a ping

#### command, with some switches after it. This command would ALSO need to be validly inserted

#### as sql injection. It appears that if you know the endpoint and you have credentials (or a valid

#### session, etc), it isn’t entirely impossible to fingerprint the database server. If the server is

#### rendering the content before it is shipped off to the client (and mitigates sql injection), it seems

#### that sqlmap has little to no power to fingerprint those databases (and servers). It is clear that the

#### content that sqlmap uses to exploit endpoints is predefined in a list, and can infer a limited

#### amount of context.

## 3. COMMIX

Thank goodness these tools are a bit complicated to use, otherwise I feel like we would have more
compromised websites. After a bit of looking at the documentation for commix, I crafted a simple bash
line, but it did not go as planned.

We know that command injection exists on the /comment endpoint in the hostname parameter, but I
am not yet sure how to make commix understand that. This was relatively simple to exploit using
httpie:


Note: NodeJS or javascript is not a supported language by commix. Please see the link here.

After several hours of dedicated effort, we have been unable to get this program to function as intended.
We have explored various aspects, including the character separator, the URL, the data in the POST
request, the available parameters for the payload, as well as the payload prefix and suffix. Despite our
attempts, we have not seen any indication that the payload has reached the target Node.js server. In
verbose mode, we can observe what the payload should be, but it does not appear to be transmitted to the
target server. While there may be a way to make Commix work, it is complicated and challenging to
debug. This is particularly frustrating, as I know precisely what command could be executed to chain a
command onto the system, but the documentation lacks clarity in explaining the finer details.

Commix appears to have a very limited view about how links should be exploited. While it is possible for
the endpoint to be exploited with command injection this was not as easy as the documentation implies.
There is an example provided in the documentation for a similar application where the same command
did not work.

We initially tried with commands like this:
└─`$ commix --url="http://127.0.0.1:8080/?page=comments&hostname=www.google.com"`

But we were unable to identify any vulnerabilities like the above command.

Managed to make Commix work with the following command:
└─$ commix --url="http://127.0.0.1:8080/ping" \


--data="hostname=INJECT_HERE" \

- p hostname \
--ignore-redirects

Results:



Testing another command:
└─$ commix --url="http://127.0.0.1:8080/ping" \
--data="hostname=INJECT_HERE" \

- p hostname \
--technique=c


Upon inspecting the tool behavior with the command -v 3 for verbose, we can see that each request is
redirecting back to the homepage. Possibly preventing Commix from identifying the vulnerability.


To address this issue, we had to temporarily remove the redirect and instead include the command output
in the response. The current endpoint looks like this:

app.post("/ping", async (req, res) => {

const hostname = req.body.hostname;
const cmd = `ping -c 4 ${hostname} 2>&1`;

try {
const { stdout } = await childProcessExec(cmd);
req.session.output = stdout;

const rtts = Array.from(stdout.matchAll(/time=([\d.]+) ms/g)).map(
(m) => m[ 1 ]

);
const statements = rtts.map(
(rtt) =>

`INSERT INTO results(hostname, round_trip_time) VALUES ('${hostname}', ${rtt})`
);
const sql = statements.join(";\n");

await dbExec(sql);
res.send(`<pre>${stdout}</pre>`);

} catch (err) {
req.session.output = err.message;


res.send(`<pre>Error: ${err.message}</pre>`);
}

// res.redirect('/?page=home')
});

The main functionality stays the same, but we remove the redirect.
Now if we test again the application with Commix using the following command:
commix --url="http://127.0.0.1:8080/ping" \
--data="hostname=INJECT_HERE" \

- p hostname \
--ignore-redirects


Commix was able to execute command injection on the target machine and granted us access to the
os_shell. We are then able to execute arbitrary commands (including downloading and running scripts) as
we have gained remote access. Commix reminds us of the importance of finding and correcting these
errors. Those who are skilled in using these exploitation tools (especially any two of them combined),
would be able to disable this machine or add it to their botnet.

## 4. OWASP ZAP

We started installing OWASP ZAP with the following command:
$ sudo apt install zaproxy --yes

We are greeted with a user interface (wow)!

Zap was able to identify most of the endpoints on our project automatically. We are really using /
endpoint for three different pages, and Zap does not identify this, leaving some endpoints unturned.


Upon entering the URL of the target server, we receive a list of alerts (located at the bottom left). There
are numerous warnings regarding CSPs, anti-clickjacking headers, and other potential issues that can be
cumbersome or easily overlooked. We will attempt to execute an attack on the /ping endpoint to
determine if ZAP identifies any injection vulnerabilities.


Zap starts running a whole bunch of requests, and within a few seconds, there is a new alert listed that we
are vulnerable to: Remote OS Command Line Injection. Zap is also kind enough to list the exact command
that triggered the warning.

We will now try the other endpoints to determine if they can find anything else.

Three additional critical warnings have appeared for cross site scripting vulnerabilities (or XSS). Zap is
even kind enough to show us the code that exploited it in a separate window.

After running the main page, we get another critical warning for Remote OS Command Injection.

This is our final list of vulnerabilities generated by Zap:


All the warnings marked with a red flag indicate the same errors identified in Project 3. It seems that Zap
effectively identifies the more significant vulnerabilities in your application. The program appears to
systematically execute a series of queries and parameters to append to the URL in order to uncover
potential vulnerabilities. Additionally, the Zap console provides clues suggesting that the program utilizes
the names of form elements to detect issues—something that previous programs, to our knowledge, did
not do.

## Summary

We conducted a comprehensive assessment of a web application to uncover vulnerabilities using tools
like SQLmap, Commix, and OWASP ZAP. SQLmap identified potential injection points but faced
challenges due to SQLite-specific limitations. Commix successfully demonstrated a time-based blind
command injection vulnerability on the /ping endpoint, highlighting weak input validation. OWASP
ZAP further revealed critical issues, including OS Command Injection and XSS vulnerabilities, pointing
to insecure configurations and improper input handling. These findings emphasize the need for robust
security measures, such as parameterized queries, strict input validation, and secure header
configurations, to safeguard against attacks.





