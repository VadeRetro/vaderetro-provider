/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class VRKeyStoreDAOException extends Exception
{
    private static final long serialVersionUID = -8696777095560829194L;

    public VRKeyStoreDAOException(String message)
    {
        super(message, null);
    }

    public VRKeyStoreDAOException(Throwable cause)
    {
        super(cause);
    }
}
