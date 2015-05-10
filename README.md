<h4>
	simple-httpsd
</h4>
<h4>
	=============
</h4>
<h4>
	A simple https deamon used for file transfer
</h4>
Usage:
<p>
	1. Create privatekey and ca:
</p>
<p>
	&nbsp;&nbsp; &nbsp;openssl genrsa -out private-key.pem 2048
</p>
<p>
	&nbsp;&nbsp; &nbsp;openssl req -new -x509 -key private-key.pem -out ca.pem -days 1024
</p>
<p>
	2. make
</p>
<p>
	3. ./simple-httpsd
</p>
<p>
	4. test with curl:
</p>
<p>
	&nbsp;&nbsp; &nbsp;curl -k -F "filename=@./file.txt"&nbsp; https://127.0.0.1:8080
</p>
<br />
