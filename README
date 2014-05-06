Disclaimer: This is not an official Google product.

Requires presence of Burp Suite extension interface in the third_party/java
directory.  To build:

$ mkdir third_party
$ cd third_party
$ mkdir java
$ cd java
$ wget http://portswigger.net/burp/extender/api/burp_extender_api.zip
$ unzip burp_extender_api.zip
$ rm burp_extender_api.zip
$ cd ../../
$ mvn package
$ java -jar target/heartbleed-1.0-SNAPSHOT.jar <host>
