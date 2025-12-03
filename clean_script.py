def main(args=None):
    """
    Cleans all of the previously saved information (The data and the RSA keys)
    """
    
    import os
    import glob

    if os.path.exists("userInfo.txt"):
        os.remove("userInfo.txt")
    if os.path.exists("private.pem"):
        os.remove("private.pem")
    if os.path.exists("public.pub"):
        os.remove("public.pub")

    # Remove all contacts bin files
    for f in glob.glob("contacts_*.bin"):
        try:
            os.remove(f)
            print(f"Removed {f}")
        except Exception as e:
            print(f"Could not remove {f}: {e}")

if __name__ == '__main__':
    main()