## Do Developers Really Understand C\# Secure Coding Guidelines? A Large-Scale Study on Stack Overflow

Mapping Microsoft C# Security Recommendations to CWE

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
	<tr >
	    <td rowspan="10">MSS</td>
	    <td>Securing resource access.</td>
	    <td>
        <p>CWE-284: Improper Access Control</p>
        <p>CWE-114: Process Control</p>
      </td>
	</tr>
	<tr>
	    <td>Security-neutral code</td>
	    <td>CWE-248: Uncaught Exception</td>
	</tr>
	<tr>
	    <td>Application code that isn't a reusable component</td>
	    <td>CWE-922: Insecure Storage of Sensitive Information</td>
	</tr>
	<tr><td>Managed wrapper to native code implementation</td>
	    <td>
        <p>CWE-285: Improper Authorization</p>
        <p>CWE-732: Incorrect Permission Assignment for Critical Resource</p>
      </td>
	</tr>
	<tr>
	    <td>Library code that exposes protected resources</td>
	    <td>
        <p>CWE-732: Incorrect Permission Assignment for Critical Resource</p>
        <p>CWE-668: Exposure of Resource to Wrong Sphere</p>
        <p>CWE-285: Improper Authorization</p>
        <p>CWE-284: Improper Access Control</p>
      </td>
	</tr>
	<tr>
	    <td>Securing State Data</td>
	    <td>
        <p>CWE-921: Storage of Sensitive Data in a Mechanism without Access Control</p>
        <p>CWE-200: Exposure of Sensitive Information to an Unauthorized Actor</p>
      </td>
	</tr>
	<tr>
	    <td>Security and User Input</td>
	    <td>CWE-20: Improper Input Validation</td>
	</tr>
	<tr>
	    <td >Security and Race Conditions</td>
	    <td>CWE-366: Race Condition within a Thread</td>
	</tr>
  <tr>
	    <td >Security and On-the-Fly Code Generation</td>
	    <td>CWE-94: Improper Control of Generation of Code ('Code Injection')</td>
	</tr>
  <tr>
	    <td >Role-Based Security</td>
	    <td>CWE-286: Incorrect User Management</td>
	</tr>
</table>
