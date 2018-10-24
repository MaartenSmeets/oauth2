package nl.amis.identityasserter;
 
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import oracle.adf.share.logging.ADFLogger;

/*package*/ class JWTCallbackHandlerImpl implements CallbackHandler
{
  private String userName; // the name of the user from the identity assertion token
  private static ADFLogger logger = ADFLogger.createADFLogger(JWTCallbackHandlerImpl.class);
  
  /*package*/ JWTCallbackHandlerImpl(String user)
  {
    userName = user;
    logger.info("Callback handler initialized with user: "+user);
  }
 
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException
  {
    logger.info("handle called");
    // loop over the callbacks
    for (int i = 0; i < callbacks.length; i++) {
 
      Callback callback = callbacks[i];
 
      // we only handle NameCallbacks
      if (!(callback instanceof NameCallback)) {
        logger.severe("UnsupportedCallbackException");
        throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
      }
 
      // send the user name to the name callback:
      NameCallback nameCallback = (NameCallback)callback;
      nameCallback.setName(userName);
    }
  }
}