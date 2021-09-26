---
layout: post
title: Stealing Cookies through Request Smuggling leading to Account Takeover
subtitle: How you could mass exploit users through Request Smuggling!
tags: [Request Smuggling, Account Takeover]
comments: true
---

Ever heard of Request Smuggling? It was recently popularized by James Kettle - Director of PortSwigger. A very dangerous critical vulnerability - if exploited can lead to mass arbitrary account takeovers, PII information leakage and what not.

In this article, I'd like to demostrate how I was recently able to discover, exploit and reveal victim's cookies through Request DeSync Attack/Request Smuggling. 


## Application Recon & Discovery

Before testing for certain bug types, my methodology when auditing an application always revolve around using the application as an intended user. I'd like to overall assess what requests are being sent, if any interesting header is being leaked, any interesting parameters to play with and then go down the rabbithole! 


Performing some reconnaissance and looking for open ports, I noticed, that this application had http port 5000 open with Gunicorn 20.0.0.


![app](https://i.imgur.com/cIxMtmC.png)


We notice there's a sign in functionality. Trying some quick default credentials do not seem to work, but it seems like we can register see what's inside.

![app](https://i.imgur.com/4AOlqkX.png)


Quickly signing up, assessing the features, one of the main features you could do is to leave comments on a public post or create your own notes that's private to you under the notes tab.

![app](https://i.imgur.com/BovsRPc.png)

As the functionality of the app is really limited, trying a very basic injection on the comments do not seem to be rendered.

![app](https://i.imgur.com/79cTBSL.png)

Playing with the app back and forth, and trying to access notes that aren't authorized to us doesn't seem to work and throws an error. I kept testing other parameters to yield out some interesting behavior but couldn't find anything worth investigating. Decided to take a break and hit back later.


## Digging Deeper

Quick break and decided to spin up the app again. This time, I clicked all the buttons on the app as much as I can and intercepted the request through Burp. I spent time going through each and every request, but while looking at the response header something stood out.

![app](https://i.imgur.com/mAkHVmS.png)

We can see this response header called `Via: haproxy ` which seems to be a front-end load balancer. We also know that from previous reconnaissance that it's running `Gunicorn 20.0.0`


Let's investigate Gunicorn futher. Going through the changelogs of Gunicorn, we can see that Gunicorn 20.0 - which is released on October 10th 2019 which is almost 2 years ago.

![app](https://i.imgur.com/WAyyWPm.png)

Now, there must be something in here. If we look at Gunicorn 20.1 for example, 

![app](https://i.imgur.com/0EdTYRO.png)

We notice that they've fixed *chunked encoding support to prevent any request smuggling*. Now that rings a bell, which confirms that the 20.0.0 Gunicorn version is vulnerable to Request Smuggling.

Request Smuggling attacks are not the easiest attacks to pull off, doing a quick google search, there's a writeup on haproxy request smuggling by Nathan Davison. https://nathandavison.com/blog/haproxy-http-request-smuggling

I'll demonstrate how you can apply this technique over here.

## Introduction to Request Smuggling

I'll briefly explain why Request Smuggling occurs in the first place. A lot of these examples are taken from PortSwigger's Request Smuggling article: https://portswigger.net/web-security/request-smuggling - for more detailed understanding, I'd highly recommend checking this article out.

Basically, the front-end server wants to send several HTTP Request over the same backend connection. This is primarly done due to efficiency reaons. It's much faster to send them over the same connection.

In order for this to work, the frontend and backend server needs to agree on some kind of boundary between the request so they both have this understanding of where requests starts and where it stops.

In order to define this boundary between the request and the HTTP Specification, there's two ways -- Content Length Header & Transfer Encoding header which kind of does the same thing but in a different way. 

Let's look into how both of them ways.

Content length is just saying how many bytes does the body of the message have. 

![app](https://i.imgur.com/cnSiYN2.png)

Transfer encoding is pretty much the same, but the format is a bit different.

![app](https://i.imgur.com/hyD0H3J.png)

Here, the transfer encoding is chunked, but it is telling us the size here which is 'b' represented as hexadecimal, which is 11. So the size is specified in the body of the request.

![app](https://i.imgur.com/yxymd4M.png)

At the end, there's one 0 chunk - which indicates the end of the request.

## Content-Length / Transfer Encoding Request Smuggling Vulnerability


![app](https://i.imgur.com/0VClPN3.png)

In this type of Request Smuggling Vulnerability, they define both headers -- Content Length & Transfer-Encoding in the same message -- which usually don't occur together.

So one of them, i.e the frontend could be reading the Content-Length header and determines that the request body is 13 bytes long up to the end of SMUGGLED. 

But when the backend processes the same request, it only interprets the Transfer-Encoding header, so treats the message body as chunked encoding and prcoesses the first chunk which is stated to be at 0 length. The next sequence of the bytes, `SMUGGLED` is left unprocessed. This `SMUGGLED` request will be processed when the next HTTP request occurs - and we want the victim to hit the next request at this point so that we can grab his request.

##  Request Smuggling in HAProxy & Gunicorn

In this specific use case, 

![app](https://i.imgur.com/3e7nEBb.png)

As shown above, we specify Content-Length & Transfer-Encoding at the same time -- but it's processing it correctly.

In the backend, it's ignoring the Content-Length and just using the Transfer-Encoding chuncked here. It is not sending the X here at all, so in this specific case, we can conclude that both the frontend & backend are using chuncked encoding and the request to be smuggled is being dropped.

However, there's this specific case where this is not true.

If you put a vertical tab i.e, \x0b in front of the chunk tier, this will transfer the whole thing. In this case, the frontend is  using the Content-Length header and passes the whole request to the backend server.

![app](https://i.imgur.com/XZQPYHU.png)


So now once the request reaches the backend, it's going to use the Transfer Encoding header which will allow us to perform Request Smuggling.

To quickly summarize before we implement this attack,

1. If we include both headers at the same time, i.e Content-Length & Transfer-Encoding, the HAProxy(Front-End Server) will look at the Transfer Encoding: chunked and thus processing it correctly, making it impossible to smuggle the request.

2. However, if we include \0xb or \0xc character on the Transfer-Encoding header, the HA Proxy(Front-End Server) looks at the Content-Length & will forward the whole request where as the backend server(Gunicorn) will use the Transfer-Encoding header instead, effectively poisoning the socket. The data after the 0 will then be prepended when the next new request hits.


## Implementing the Attack

Let's look into how we can take the ascii character table and learn how to create a vertical tab. 

![app](https://i.imgur.com/xaiY3aR.png)

![app](https://i.imgur.com/DTJGhhu.png)

Printf is going to show nothing here, what we can do here is base64 encode -> Copy to Burp -> Base64 decode to get the tab working.

![app](https://i.imgur.com/5VoYAU5.png)

Decoding it, we should now see the vertical tab being added.

![app](https://i.imgur.com/LZV1k06.png)


The next job is to find an endpoint where we can populate the smuggled request. The app currently has a feature to add your notes, we can use this endpoint to populate the requests of our victim.

So sending a request like below:

![app](https://i.imgur.com/WU0xMTn.png)

What happens here is, HAProxy will forward the whole request to the backend server by looking at the Content-Length Header. Gunicorn will look at the Transfer-Encoding header and will only process the first part of the GET Request.

The `POST /notes ` request now stays in the buffer until a new request comes through.

Now when the victim makes a new request, the `POST /notes` will be prepended to the victim's request and the victim's request will be populated to the `note` parameter.

Keep in mind that the content-length of the POST /notes has to be guessed here, to play it safe it’s better to keep somewhere in the safe range of 200-300 CL. We do not want to keep the Content-Length so high as well - which might potentially cause the server to hang if the requirement is not satisfied.

Forwarding the above request, we can see that we poisoned our victim’s request and it was posted to our notes, as we never made a `GET request to /notes/delete`

![app](https://i.imgur.com/MxpLOsI.png)

Our Request Smuggling attack was successful and we can now takeover the victim with the session cookie and login as the victim leading to complete account takeover.

Hope you all enjoying reading my thought process behind this attack.


