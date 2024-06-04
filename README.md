LIFERAY JSON DESERIALIZATION REPORT
========================
What is Serialization and Deserialization?
---------
>**Serialization** is the process of converting a data structure or object into a format that can be easily stored, transmitted, or persisted. The resulting serialized data is often in a standardized, platform-independent format, such as JSON, XML, or binary data.


>**Deserialization** is the process of reconstructing a data structure or object from its serialized form. It involves interpreting the serialized data and creating an equivalent object or data structure.

Security risks arise when developers do not apply security check for user's input, leading to the injection of malicious payload which insert system commands through deserialization process. Let's examine this Java code to understand more:
```
import java.io.*;
import java.util.Scanner;

public class InsecureDeserializationVulnerable {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter a string:");
        String input = scanner.nextLine();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(input.getBytes()));
        Object obj = ois.readObject();
        ois.close();

        System.out.println(obj.getClass().getName());
    }
}
```
In this code snippet, our input will be directly implemented by the `readObject()` function. The code doesn't have any validation, therefore it will deserialize arbitrary code from user's input.

[CVE-2019-16891] Liferay RCE via JSON Deserialization
---------

Liferay is an open-source web portal platform which is written in Java. The CVE-2019-16891 is one of the vulnerability occurred in Liferay. This vulnerability exploits the deserialization process in Liferay, which does not properly validated.

The lab setup will be skipped. After successfully install liferay, we have this main page
![main_page]()

Turning the intercept on in Burpsuite, I notice that there's a POST request send to the server with request body looks interesting

![poller-receive]()
The value of the `pollerRequest` is in json, which might be deserialized after sending to the server.
I added many breakpoints and there's one got triggered is this one

![first_breakpoint]()

Tracing the stack, we can identify the flow of this process:
```HttpServlet.service() -> PollerServlet.service() -> PollerServlet.getContent() -> PollerRequestHandlerUltil.getPollerHeader() -> PollerRequestHandlerImpl.getPollerHeader() -> PollerRequestHandlerImpl.parsePollerRequestParameters() -> JSONFactoryImpl.deserialize()```

We can see that `JSONFactoryImpl.deserialize(String)`  is in charge of deserialization. This method calls to `org.jabsorb.JSONSerializer.fromJSON()` then calls to `JSONSerializer.unmarshall()` to continue deserialize the object.

![unmarshall]()


After analyzing, I identify that `com.mchange.v2.c3p0.mbean.C3P0PooledDataSource` is the class that can be exploited. `ysoserial` is a great tool for us as it can generate the payload. 
 First we need to send a malicious request to the server to change the value of the class
 
 ![malicious request]()

Then ysoserial will connect to the server and then inject payload and open calculator

![done]()
