/**
 * @fileoverview Node JS Library for Message protocols
 *
 * @description This is a module that implements the protocol messages in OAuth2
 * and OpenID Connect.
 * <pre>
 * The OpenID Connect and OAuth2 standards both defines lots of messages. Requests that are sent 
 * from clients to servers and responses from servers to clients.
 * <pre>
 * For each of these messages a number of parameters (claims) are listed, some of them required 
 * and some optional. Each parameter are also assigned a data type.
 * <pre>
 * What is also defined in the standard is the on-the-wire representation of these messages. Like
 * if they are the fragment component of a redirect URI or a JSON document transferred in the body
 * of a response.
 * <pre>
 * The Message class is supposed to capture all of this. 
 * <pre>
 * Using this class you should be able to: <pre>
 *      - build a message <pre>
 *      - verify that a message’s parameters are correct, that all that are marked as required are 
 *          present and all (required and optional) are of the right type <pre>
 *      - serialize the message into the correct on-the-wire representation <pre>
 *      - deserialize a received message from the on-the-wire representation into a Message instance. <pre>
 * <pre>
 * The Message class is the base class the oidcmsg package contains subclasses representing all the
 * messages defined in OpenID Connect and OAuth2.
 * <pre>
 * What oidcmsg also contains are tools for handling keys.
 * <pre>
 * There is the KeyBundle class that can handle keys that have the same origin. That for instance 
 * comes from one file or has been fetched from a web site.
 * <pre>
 * The KeyJar class stores keys from many issuers. Where the keys for each issuer is kept in one 
 * or more KeyBundle instances.
 */