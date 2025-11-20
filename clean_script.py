def main(args=None):
    """
    Cleans all of the previously saved information (The data and the RSA keys)
    """
    
    import os

    if os.path.exists("userInfo.txt"):
        os.remove("userInfo.txt")
    if os.path.exists("private.pem"):
        os.remove("private.pem")
    if os.path.exists("public.pub"):
        os.remove("public.pub")

if __name__ == '__main__':
    main()