package nl.amis.policies;

import oracle.adf.share.logging.ADFLogger;

import oracle.wsm.common.sdk.IContext;
import oracle.wsm.common.sdk.IMessageContext;
import oracle.wsm.common.sdk.IResult;
import oracle.wsm.common.sdk.Result;
import oracle.wsm.common.sdk.WSMException;
import oracle.wsm.policy.model.IAssertion;
import oracle.wsm.policy.model.IAssertionBindings;
import oracle.wsm.policy.model.IConfig;
import oracle.wsm.policy.model.IPropertySet;
import oracle.wsm.policy.model.ISimpleOracleAssertion;
import oracle.wsm.policy.model.impl.SimpleAssertion;
import oracle.wsm.policyengine.IExecutionContext;
import oracle.wsm.policyengine.impl.AssertionExecutor;

public class CustomRolePermissionPolicy extends AssertionExecutor {
    private static ADFLogger logger = ADFLogger.createADFLogger(CustomRolePermissionPolicy.class);

    public CustomRolePermissionPolicy() {
        super();
    }

    @Override
    public IResult execute(IContext Context) throws WSMException {
        logger.info("Request received");
        logger.info("Context is of class: "+Context.getClass().getName());
        
        try {
            //Retrieve Policy bindings from Policy File
            IAssertionBindings bindings = ((SimpleAssertion) (this.assertion)).getBindings();
            //Get Policy Config name from Policy File
            IConfig config = bindings.getConfigs().get(0);
            //Get Property set name of policy
            IPropertySet propertyset = config.getPropertySets().get(0);
            String valid_roles = propertyset.getPropertyByName("valid_roles").getValue();
            logger.info("Valid roles: "+valid_roles);
            String valid_users = propertyset.getPropertyByName("valid_users").getValue();
            logger.info("Valid users: "+valid_users);
            
            IMessageContext messageContext = (IMessageContext) Context;
            logger.info("messageContext properties: "+messageContext.getAllProperties().toString());

            String security_subject = "";    
            try {
                security_subject = messageContext.getProperty(IMessageContext.SECURITY_SUBJECT).toString();
            } catch (NullPointerException e) {
                logger.info("Security subject not found");
            }
            
            String user_name = "";
            
            try {
                user_name = messageContext.getProperty(IMessageContext.USER_NAME).toString();
            } catch (NullPointerException e) {
                logger.info("User name not found");
            }

            IResult result = new Result();
            if (valid_users != null && valid_users.trim().length() > 0) {
                String[] valid_users_array = valid_users.split(",");
                boolean isPresent = false;
                for (String valid_user : valid_users_array) {
                    if (user_name.equals(valid_user.trim())) {
                        isPresent = true;
                    }
                }
                if (isPresent) {
                    result.setStatus(IResult.SUCCEEDED);
                } else {
                    result.setStatus(IResult.FAILED);
                    result.setFault(new WSMException(WSMException.FAULT_FAILED_CHECK));
                }
            } else {
                result.setStatus(IResult.SUCCEEDED);
            }
            String resultString;
            switch (result.getStatus()) {
            case IResult.SUCCEEDED:
                resultString = "SUCCEEDED";
                break;
            case IResult.FAILED:
                resultString = "FAILED";
                break;
            case IResult.SUSPENDED:
                resultString = "SUSPENDED";
                break;
            case IResult.SKIP:
                resultString = "SKIP";
                break;
            default:
                resultString = "Unknown";
                break;
            }
            logger.info("Request completed with: " + resultString);

            return result;
        } catch (Exception e) {
            logger.severe("Request not completed",e);
            throw new WSMException(WSMException.FAULT_FAILED_CHECK, e);
        }
    }
    //The init() method is invoked by the OWSM framework whenever the configuration of the policy attachment is updated (i.e. its property values are changed).
    @Override
    public void init(IAssertion assertion, IExecutionContext econtext, IContext Context) throws WSMException {
        this.assertion = assertion;
        this.econtext = econtext;

    }

    public oracle.wsm.policyengine.IExecutionContext getExecutionContext() {
        return this.econtext;
    }

    public boolean isAssertionEnabled() {
        //return policy enforce value
        return ((ISimpleOracleAssertion) this.assertion).isEnforced();
    }

    public String getAssertionName() {
        return this.assertion
                   .getQName()
                   .toString();
    }

    @Override
    public void destroy() {
    }

    public oracle.wsm.common.sdk.IResult postExecute(oracle.wsm.common.sdk.IContext p1) {
        IResult result = new Result();
        result.setStatus(IResult.SUCCEEDED);
        return result;
    }

}
