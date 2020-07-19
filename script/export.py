def main():
    with open("libcef.txt", "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 4:
                ord = int(parts[0])
                name = parts[3]
                with open('redir.h', 'a') as f:
                    f.write(f'#pragma comment(linker, "/export:{name}=libcef_orig.{name},@{ord}")\n')

if __name__ == "__main__":
    main()