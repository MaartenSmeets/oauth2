package nl.amis.identityasserter;
 
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import weblogic.management.security.ProviderMBean;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;
import javax.servlet.http.HttpServletRequest;
 
public final class JWTIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2
{
  final static private String TOKEN_TYPE   = "JWTPerimeterAtnToken"; 
  final static private String TOKEN_PREFIX = "username="; 
 
  private String description; 
 
  public void initialize(ProviderMBean mbean, SecurityServices services)
  {
    System.out.println("JWTIdentityAsserterProviderImpl.initialize");
    JWTIdentityAsserterMBean myMBean = (JWTIdentityAsserterMBean)mbean;
    description                         = myMBean.getDescription() + "\n" + myMBean.getVersion();
  }
 
  public String getDescription()
  {
    return description;
  }
 
  public void shutdown()
  {
    System.out.println("JWTIdentityAsserterProviderImpl.shutdown");
  }
 
  public IdentityAsserterV2 getIdentityAsserter()
  {
    return this;
  }
 
  public CallbackHandler assertIdentity(String type, Object token, ContextHandler context) throws IdentityAssertionException
  {
    System.out.println("JWTIdentityAsserterProviderImpl.assertIdentity");
    System.out.println("\tType\t\t= "  + type);
    System.out.println("\tToken\t\t= " + token);
 
    Object requestValue = context.getValue("com.bea.contextelement.servlet.HttpServletRequest");
    if ((requestValue == null) || (!(requestValue instanceof HttpServletRequest)))
      {
       System.out.println("do nothing");
       }
   else{
       HttpServletRequest request = (HttpServletRequest) requestValue;
       java.util.Enumeration names = request.getHeaderNames();
        while(names.hasMoreElements()){
            String name = (String) names.nextElement();
            System.out.println(name + ":" + request.getHeader(name));
        }
   }
 
    // check the token type
    if (!(TOKEN_TYPE.equals(type))) {
      String error =
        "JWTIdentityAsserter received unknown token type \"" + type + "\"." +
        " Expected " + TOKEN_TYPE;
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }
 
    // make sure the token is an array of bytes
    if (!(token instanceof byte[])) {
      String error = 
        "JWTIdentityAsserter received unknown token class \"" + token.getClass() + "\"." +
        " Expected a byte[].";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }
 
    // convert the array of bytes to a string
    byte[] tokenBytes = (byte[])token;
    if (tokenBytes == null || tokenBytes.length < 1) {
      String error =
        "JWTIdentityAsserter received empty token byte array";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }
 
    String tokenStr = new String(tokenBytes);
 
    // make sure the string contains "username=someusername
    if (!(tokenStr.startsWith(TOKEN_PREFIX))) {
      String error =
        "JWTIdentityAsserter received unknown token string \"" + type + "\"." +
        " Expected " + TOKEN_PREFIX + "username";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }
 
    // extract the username from the token
    String userName = tokenStr.substring(TOKEN_PREFIX.length());
    System.out.println("\tuserName\t= " + userName);
 
    // store it in a callback handler that authenticators can use
    // to retrieve the username.
    return new JWTCallbackHandlerImpl(userName);
  }
 
  public AppConfigurationEntry getLoginModuleConfiguration()
  {
    return null;
  }
 
  public AppConfigurationEntry getAssertionModuleConfiguration()
  {
    return null;
  }
 
  public PrincipalValidator getPrincipalValidator() 
  {
    return null;
  }
}