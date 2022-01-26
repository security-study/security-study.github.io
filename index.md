## Do Developers Really Understand C\# Secure Coding Guidelines? A Large-Scale Study on Stack Overflow

### Mapping Microsoft C# Common Security Coding Guidelines to CWE



<table>
	<tr>
	    <th colspan="2">Microsoft</th>
	    <th>CWE</th>  
	</tr >
	<tr >
	    <td rowspan="11">MSC</td>
	    <td>Use the checked keyword to control the overflow-checking context for integral-type arithmetic operations and conversions.</td>
	    <td>CWE-190: Integer Overflow or Wraparound</td>
	</tr>
	<tr>
	    <td>Always use the most restrictive data type for parameters.</td>
	    <td>CWE-233: Improper Handling of Parameters</td>
	</tr>
	<tr>
	    <td>Do not make decisions based on file names.</td>
	    <td>CWE-646: Reliance on File Name or Extension of Externally-Supplied File</td>
	</tr>
	<tr>
	    <td>Never, ever hardcode passwords or other sensitive information into your application.</td>
	    <td>CWE-798: Use of Hard-coded Credentials</td>
	</tr>
	<tr><td>Always validate input that is used to generate SQL queries.</td>
	    <td>CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')</td>
	</tr>
	<tr>
	    <td>Validate all inputs into your methods.</td>
	    <td>CWE-20: Improper Input Validation</td>
	</tr>
	<tr>
	    <td>Do not display exception information: it provides any would-be attacker with valuable clues.</td>
	    <td>CWE-209: Generation of Error Message Containing Sensitive Information</td>
	</tr>
	<tr>
	    <td>Ensure that your application works while running with the least possible permissions.</td>
	    <td>
        <p>CWE-250: Execution with Unnecessary Privileges</p>
        <p>CWE-266: Incorrect Privilege Assignment</p>
      </td>
	</tr>
	<tr>
	    <td >Do not use your own encryption algorithms.</td>
	    <td>
        <p>CWE-327: Use of a Broken or Risky Cryptographic Algorithm</p>
        <p>CWE-1240: Use of a Risky Cryptographic Primitive</p>
      </td>
	</tr>
  <tr>
	    <td>Give your assemblies strong names.</td>
	    <td>CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere</td>
	</tr>
  <tr>
	    <td>Do not store sensitive information in XML or other configuration files.</td>
	    <td>CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory</td>
	</tr>
</table>


---


### Mapping Microsoft C# System Security Coding Guidelines to CWE

<table>
	<tr>
	    <th>Microsoft</th>
	    <th>Type</th> 
	    <th>Description</th> 
	    <th>CWE</th>  
	</tr >
	<tr>
	    <td rowspan="10">MSS</td>
	    <td><p><b>Securing resource access</b></p></td>
	    <td>
		    <p>When designing and writing your code, you need to protect and limit the access that code has to resources, 
		       especially when using or invoking code of unknown origin. So, keep in mind the following techniques to ensure 
		       your code is secure:</p>
	            <ul>
		    <li><p>Do not use Code Access Security (CAS).</p></li>
		    <li><p>Do not use partial trusted code.</p></li>
		    <li><p>Do not use the AllowPartiallyTrustedCaller attribute (APTCA).</p></li>
		    <li><p>Do not use .NET Remoting.</p></li>
	            <li><p>Do not use Distributed Component Object Model (DCOM).</p></li>
		    <li><p>Do not use binary formatters.</p></li>
		    </ul>
		    <p>Code Access Security and Security-Transparent Code are not supported as a security boundary with partially trusted
			    code. We advise against loading and executing code of unknown origins without putting alternative security measures
			    in place. The alternative security measures are:</p>
		    <ul>
		    <li><p>Virtualization</p></li>
		    <li><p>AppContainers</p></li>
		    <li><p>Operating system (OS) users and permissions</p></li>
		    <li><p>Hyper-V containers</p></li>
		    </ul>
		</td>
	    <td>
        <p>CWE-284: Improper Access Control</p>
        <p>CWE-114: Process Control</p>
      </td>
	</tr>
	<tr>
	        <td><p><b>Security-neutral code</b></p></td>
		<td>
			<p>Security-neutral code does nothing explicit with the security system. It runs with whatever permissions it receives.
				Although applications that fail to catch security exceptions associated with protected operations (such as using files, 
				networking, and so on) can result in an unhandled exception, security-neutral code still takes advantage of the security 
				technologies in .NET.</p>
			<p>A security-neutral library has special characteristics that you should understand. Suppose your library provides API elements
				that use files or call unmanaged code. If your code doesn't have the corresponding permission, it won't run as described.
				However, even if the code has the permission, any application code that calls it must have the same permission in order to
				work. If the calling code doesn't have the right permission, a SecurityException appears as a result of the code access 
				security stack walk.</p>
		</td>
	    <td>CWE-248: Uncaught Exception</td>
	</tr>
	<tr>
	    <td><p><b>Application code that isn't a reusable component</b></p></td>
	    <td>
		    <p>If your code is part of an application that won't be called by other code, security is simple and special coding might not be required.
			    However, remember that malicious code can call your code. While code access security might stop malicious code from accessing resources, 
			    such code could still read values of your fields or properties that might contain sensitive information.</p>
		    <p>Additionally, if your code accepts user input from the Internet or other unreliable sources, you must be careful about malicious input.</p>
		</td>
	    <td>CWE-922: Insecure Storage of Sensitive Information</td>
	</tr>
	<tr>
	    <td><p><b>Managed wrapper to native code implementation</b></p></td>
	    <td>
		<p>Typically in this scenario, some useful functionality is implemented in native code that you want to make available to managed code. 
			Managed wrappers are easy to write using either platform invoke or COM interop. However, if you do this, callers of your wrappers
			must have unmanaged code rights in order to succeed. Under default policy, this means that code downloaded from an intranet or the 
			Internet won't work with the wrappers.</p>
		<p>Instead of giving unmanaged code rights to all applications that use these wrappers, it's better to give these rights only to the wrapper code. 
			If the underlying functionality exposes no resources and the implementation is likewise safe, the wrapper only needs to assert its rights, 
			which enables any code to call through it. When resources are involved, security coding should be the same as the library code case described 
			in the next section. Because the wrapper is potentially exposing callers to these resources, careful verification of the safety of the native 
			code is necessary and is the wrapper's responsibility.</p>
		</td>
	    <td>
        <p>CWE-285: Improper Authorization</p>
        <p>CWE-732: Incorrect Permission Assignment for Critical Resource</p>
      </td>
	</tr>
	<tr>
	    <td><p><b>Library code that exposes protected resources</b></p></td>
	    <td>
		    <p>The following approach is the most powerful and hence potentially dangerous (if done incorrectly) for security coding: your library serves 
			    as an interface for other code to access certain resources that aren't otherwise available, just as the .NET classes enforce permissions 
			    for the resources they use. Wherever you expose a resource, your code must first demand the permission appropriate to the resource 
			    (that is, it must perform a security check) and then typically assert its rights to perform the actual operation.</p>
		</td>
	    <td>
        <p>CWE-732: Incorrect Permission Assignment for Critical Resource</p>
        <p>CWE-668: Exposure of Resource to Wrong Sphere</p>
        <p>CWE-285: Improper Authorization</p>
        <p>CWE-284: Improper Access Control</p>
      </td>
	</tr>
	<tr>
	    <td><p><b>Securing State Data</b></p></td>
	    <td>
		    <p>Applications that handle sensitive data or make any kind of security decisions need to keep that data under their own control and cannot 
			    allow other potentially malicious code to access the data directly. The best way to protect data in memory is to declare the data 
			    as private or internal (with scope limited to the same assembly) variables. However, even this data is subject to access you should 
			    be aware of:</p>
		    <ul>
		    <li><p>Using reflection mechanisms, highly trusted code that can reference your object can get and set private members.</p></li>
		    <li><p>Using serialization, highly trusted code can effectively get and set private members if it can access the corresponding data in the serialized 
			    form of the object.</p></li>
		    <li><p>Under debugging, this data can be read.</p></li>
		    </ul>
		    <p>Make sure none of your own methods or properties exposes these values unintentionally.</p>
		</td>
	    <td>
        <p>CWE-921: Storage of Sensitive Data in a Mechanism without Access Control</p>
        <p>CWE-200: Exposure of Sensitive Information to an Unauthorized Actor</p>
      </td>
	</tr>
	<tr>
	    <td><p><b>Security and User Input</b></p></td>
	    <td>
		    <p>User data, which is any kind of input (data from a Web request or URL, input to controls of a Microsoft Windows Forms application, and so on), 
			    can adversely influence code because often that data is used directly as parameters to call other code. This situation is analogous to 
			    malicious code calling your code with strange parameters, and the same precautions should be taken. User input is actually harder to make 
			    safe because there is no stack frame to trace the presence of the potentially untrusted data.</p>
		    <p>These are among the subtlest and hardest security bugs to find because, although they can exist in code that is seemingly unrelated to security, 
			    they are a gateway to pass bad data through to other code. To look for these bugs, follow any kind of input data, imagine what the range of 
			    possible values might be, and consider whether the code seeing this data can handle all those cases. You can fix these bugs through range 
			    checking and rejecting any input the code cannot handle.</p>
		    <p>Some important considerations involving user data include the following:</p>
		    <ul>
		    <li><p>Any user data in a server response runs in the context of the server's site on the client. If your Web server takes user data and inserts it 
			    into the returned Web page, it might, for example, include a script tag and run as if from the server.</p></li>
		    <li><p>Remember that the client can request any URL.</p></li>
		    <li><p>Consider tricky or invalid paths:</p></li>
			    <ul>
				    <li><p>..\ , extremely long paths.</p></li>
				    <li><p>Use of wild card characters (*).</p></li>
				    <li><p>Token expansion (%token%).</p></li>
				    <li><p>Strange forms of paths with special meaning.</p></li>
				    <li><p>Alternate file system stream names such as <code>filename::$DATA</code>.</p></li>
				    <li><p>Short versions of file names such as <code>longfi~1</code> for <code>longfilename</code>.</p></li>
			    </ul>
		    <li><p>Remember that Eval(userdata) can do anything.</p></li>
		    <li><p>Be wary of late binding to a name that includes some user data.</p></li>
		    <li><p>If you are dealing with Web data, consider the various forms of escapes that are permissible, including:</p></li>
			    <ul>
				    <li><p>Hexadecimal escapes (%nn).</p></li>
				    <li><p>Unicode escapes (%nnn).</p></li>
				    <li><p>Overlong UTF-8 escapes (%nn%nn).</p></li>
				    <li><p>Double escapes (%nn becomes %mmnn, where %mm is the escape for '%').</p></li>
			    </ul>
		    <li><p>Be wary of user names that might have more than one canonical format. For example, you can often use either the MYDOMAIN\<em>username</em> 
			    form or the <em>username</em>@mydomain.example.com form.</p></li>
		    </ul>
		</td>
	    <td>CWE-20: Improper Input Validation</td>
	</tr>
	<tr>
	    <td ><p><b>Security and Race Conditions</b></p></td>
	    <td>
		<p>Another area of concern is the potential for security holes exploited by race conditions. There are several ways in which this might happen. 
			The subtopics that follow outline some of the major pitfalls that the developer must avoid.</p>
		<p><b>Race Conditions in the Dispose Method</b></p>
		<p>If a class's <strong>Dispose</strong> method (for more information, see <a href="../garbage-collection/" data-linktype="relative-path">Garbage Collection</a>)                   is not synchronized, it is possible that cleanup code inside <strong>Dispose</strong> can be run more than once, as shown in the following example.</p>
	<pre>
	<code>
void Dispose()
{  
    if (myObj != null)
    {  
        Cleanup(myObj);  
        myObj = null;  
    }  
}
	</code>
	</pre>
	        <p>Because this Dispose implementation is not synchronized, it is possible for Cleanup to be called by first one thread and then a second thread before 
			_myObj is set to null. Whether this is a security concern depends on what happens when the Cleanup code runs. A major issue with unsynchronized 
			Dispose implementations involves the use of resource handles such as files. Improper disposal can cause the wrong handle to be used, which often 
			leads to security vulnerabilities.</p>
		<p><b>Race Conditions in Constructors</b></p>
		    <p>In some applications, it might be possible for other threads to access class members before their class constructors have completely run. 
			    You should review all class constructors to make sure that there are no security issues if this should happen, or synchronize threads 
			    if necessary.</p>
		<p><b>Race Conditions with Cached Objects</b></p>
		    <p>Code that caches security information or uses the code access security Assert operation might also be vulnerable to race conditions if other 
			    parts of the class are not appropriately synchronized, as shown in the following example.</p>
		    <pre>
	<code>
	void SomeSecureFunction()
{  
    if (SomeDemandPasses())
    {  
        fCallersOk = true;  
        DoOtherWork();  
        fCallersOk = false;  
    }  
}  
void DoOtherWork()
{  
    if (fCallersOK)
    {  
        DoSomethingTrusted();  
    }  
    else
    {  
        DemandSomething();  
        DoSomethingTrusted();  
    }  
}
	</code>
	</pre>
		    <p>If there are other paths to DoOtherWork that can be called from another thread with the same object, an untrusted caller can slip past a demand.</p>
		    <p>If your code caches security information, make sure that you review it for this vulnerability.</p>
		<p><b>Race Conditions in Finalizers</b></p>
		<p>Race conditions can also occur in an object that references a static or unmanaged resource that it then frees in its finalizer. 
			If multiple objects share a resource that is manipulated in a class's finalizer, the objects must synchronize all access to that resource.</p>
	   </td>
	    <td>CWE-366: Race Condition within a Thread</td>
	</tr>
  <tr>
	<td ><p><b>Security and On-the-Fly Code Generation</b></p></td>
	<td>
		    <p>Some libraries operate by generating code and running it to perform some operation for the caller. The basic problem is generating code on behalf 
			    of lesser-trust code and running it at a higher trust. The problem worsens when the caller can influence code generation, so you must ensure 
			    that only code you consider safe is generated.</p>
	            <p>You need to know exactly what code you are generating at all times. This means that you must have strict controls on any values that you get from 
			    a user, be they quote-enclosed strings (which should be escaped so they cannot include unexpected code elements), identifiers (which should 
			    be checked to verify that they are valid identifiers), or anything else. Identifiers can be dangerous because a compiled assembly can be modified 
			    so that its identifiers contain strange characters, which will probably break it (although this is rarely a security vulnerability).</p>
	           <p>It is recommended that you generate code with reflection emit, which often helps you avoid many of these problems.</p>
	           <p>When you compile the code, consider whether there is some way a malicious program could modify it. Is there a small window of time during which 
			   malicious code can change source code on disk before the compiler reads it or before your code loads the .dll file? If so, you must protect 
			   the directory containing these files, using an Access Control List in the file system, as appropriate.</p>
	   </td>
	    <td>CWE-94: Improper Control of Generation of Code ('Code Injection')</td>
	</tr>
  <tr>
	    <td ><p><b>Role-Based Security</b></p></td>
	    <td>
	    <p>Roles are often used in financial or business applications to enforce policy. For example, an application might impose limits on the size of the transaction 
		    being processed depending on whether the user making the request is a member of a specified role. Clerks might have authorization to process 
		    transactions that are less than a specified threshold, supervisors might have a higher limit, and vice-presidents might have a still higher limit (or 
		    no limit at all). Role-based security can also be used when an application requires multiple approvals to complete an action. Such a case might be 
		    a purchasing system in which any employee can generate a purchase request, but only a purchasing agent can convert that request into a purchase order 
		    that can be sent to a supplier.</p>
	    <p>.NET role-based security supports authorization by making information about the principal, which is constructed from an associated identity, available to 
		    the current thread. The identity (and the principal it helps to define) can be either based on a Windows account or be a custom identity unrelated to 
		    a Windows account. .NET applications can make authorization decisions based on the principal's identity or role membership, or both. A role is a named 
		    set of principals that have the same privileges with respect to security (such as a teller or a manager). A principal can be a member of one or more roles.
		    Therefore, applications can use role membership to determine whether a principal is authorized to perform a requested action.</p>
	    <p>To provide ease of use and consistency with code access security, .NET role-based security provides System.Security.Permissions.PrincipalPermission objects 
		    that enable the common language runtime to perform authorization in a way that is similar to code access security checks. The PrincipalPermission 
		    class represents the identity or role that the principal must match and is compatible with both declarative and imperative security checks. You can 
		    also access a principal's identity information directly and perform role and identity checks in your code when needed.</p>
	    <p>.NET provides role-based security support that is flexible and extensible enough to meet the needs of a wide spectrum of applications. You can choose 
		    to interoperate with existing authentication infrastructures, such as COM+ 1.0 Services, or to create a custom authentication system. Role-based 
		    security is particularly well-suited for use in ASP.NET Web applications, which are processed primarily on the server. However, .NET role-based 
		    security can be used on either the client or the server.</p>
	    <p>Before reading this section, make sure that you understand the material presented in Key Security Concepts.</p>
            </td>
	    <td>CWE-286: Incorrect User Management</td>
	</tr>
</table>
