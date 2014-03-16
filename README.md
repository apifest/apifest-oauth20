#ApiFest OAuth 2.0 Server and Mapping
ApiFest consists of two main parts - ApiFest OAuth 2.0 an OAuth 2.0 server and the ApiFest Mapping Server.

##ApiFest Mapping Server
ApiFest Mapping Server (AMS) is for people who have APIs and want to expose them to the world in a safe and convinient way.
AMS is used to translate between the outside world and your internal systems. It helps you keep a consistent API facade.

###Features
- mappings are described in xml;
- can validate and authorize requests using the ApiFest OAuth20 Server;
- out-of-the-box flexible mapping options;
- easy to extend and customize;
- customizable error messages and responses;
- "online" change of all configurations;
- unlimited horizontal scalability;


##ApiFest OAuth 2.0 Server
ApiFest OAuth 2.0 Server implements OAuth 2.0 server side as per http://tools.ietf.org/html/rfc6749.
It enables the usage of access tokens in ApiFest Mapping Server.

###Features
- register new client app;
- generate access token using auth code;
- generate access token using username and password - grant_type=password;
- generate access token using client credentials - grant_type=client_credentials;
- generate access token using refresh token - grant_type=refresh_token;
- revoke access token;
- validate access token;
- pluggable storage (currently supports MongoDB and Redis);
- unlimited horizontal scalability;


##ApiFest OAuth 2.0 Server Quick start:
**1. apifest-oauth.properties file**

Here is a template of apifest-oauth.properties file:
```
oauth20.port=
oauth20.host=
expires_in.client_credentials=
expires_in.password=
db_host=
user.authenticate.endpoint=
user_id.name=
oauth20.database=
redis.sentinels=
redis.master=
```

The path to the apifest.properties file should be passed as a system variable:

***-Dproperties.file***

* **Setup ApiFest OAuth 2.0 Server host and port**

ApiFest OAuth 2.0 Server can run on different hosts and ports.
You can define this host and port in apifest-oauth.properties file -

***oauth20.host*** and ***oauth20.port***

* **Setup the type of the DB (MongoDB or Redis)

You can define the type of the DB to be used (by default MongoDB is used) - valid values are "mongodb" and "redis" (without quotes) - 

***oauth20.database***

* **Setup DB host (MongoDB)**

If MongoDB is used, define the host of the database in the following property in apifest-oauth.properties file:

***db_host***

* **Setup Redis**

If Redis is used, define Redis sentinels list(as comma-separated list) in the following property in apifest-oauth.properties file:

***redis.sentinels***

You can define the name of Redis master in the following property in apifest-oauth.properties file:

***redis.master***

* **Setup expires in times**

Defines different access tokens types expires_in (in seconds) in the following properties:

***expires_in.client_credentials*** - for client_credentials access tokens

***expires_in.password*** - for password access tokens

* **Setup authenticate endpoint in your API**

As ApiFest OAuth 2.0 Server should be able to use username and password (in case of Resource Owner Password Credentials Grant flow) for authentication, an authenticate endpoint in your 
API should be defined. For that purpose, use the following property in apifest-oauth.properties file:

***user.authenticate.endpoint***

Currently, ApiFest OAuth 2.0 Server expects the response from your API authenticate endpoint in JSON format.
Also, user unique identifier should be returned in the response so it can be used by ApiFest OAuth 2.0 Server (it will be associated with access token with grant_type=password).
The name of the JSON field containing that information is defined in property named:

***user_id.name***

  
** 2. Start ApiFest OAuth 2.0 Server **

You can start ApiFest OAuth 2.0 Server with the following command:

```java -Dproperties.file=[apifest_properties_file_path] -jar apifest-oauth20-0.1.0-jar-with-dependencies.jar```

When the server starts, you will see:
```ApiFest OAuth 2.0 Server started at [host]:[port]```