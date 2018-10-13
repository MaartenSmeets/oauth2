package nl.amis.services.tokenservice;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("resources")
public class TokenApplication extends Application {
    public Set<java.lang.Class<?>> getClasses() { 
           Set<java.lang.Class<?>> s = new HashSet<Class<?>>();
           s.add(TokenResource.class);
           return s;
    }
}
