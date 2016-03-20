/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class KeyStoreDAOException extends Exception
{
    private static final long serialVersionUID = -8696777095560829194L;

    public KeyStoreDAOException(String message)
    {
        super(message, null);
    }

    public KeyStoreDAOException(Throwable cause)
    {
        super(cause);
    }
}
