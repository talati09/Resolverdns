# DNS Resolver Project

A simple C++ DNS resolver that sends raw DNS queries to a public DNS server (like Google DNS), parses the response, and caches the results in a local JSON file.

## Features

- Resolves A records for any hostname using UDP DNS queries
- Parses and displays the resolved IP address
- Caches results in a JSON file for faster lookups
- Command-line interface

## Requirements

- C++17 or later
- [nlohmann/json](https://github.com/nlohmann/json) (for JSON cache)
- CMake (for building)
- A C++ compiler (GCC, Clang, or MSVC)
- Internet connection

## Building

1. **Clone the repository:**
    ```sh
    git clone https://github.com/talati09/Resolverdns.git
    cd Resolverdns
    ```
2. **Install the JSON library (if needed):**
   - Option 1: Use system package manager (e.g., `apt install nlohmann-json-dev`)
   - Option 2: Use CMake's `FetchContent` in the project (already supported)

3. **Build with CMake:**
    ```sh
    mkdir build
    cd build
    cmake ..
    make
    ```

4. **Run the resolver:**
    ```sh
    ./dns_resolver
    ```

## Usage

When you run the program, enter the hostname you want to resolve:

```
Enter the hostname to resolve: google.com
```

The program will:
- Check the cache for a saved IP
- If not cached, send a DNS query to 8.8.8.8
- Print the resolved IP address
- Save the result to `data/cache.json`

## Project Structure

```
projectdns/
├── src/
│   ├── main.cpp
│   ├── dns_resolver.cpp
│   ├── parser.cpp
│   ├── cache.cpp
│   ├── utils.cpp
│   └── headers/
│       ├── dns_resolver.h
│       ├── dns_structs.h
│       ├── parser.h
│       ├── cache.h
│       └── utils.h
├── data/
│   └── cache.json
├── CMakeLists.txt
└── README.md
```

## Troubleshooting

- **Cache file errors:**  
  Make sure the `data` folder exists and you have read/write permissions for `cache.json`.

- **No IP resolved:**  
  Check your internet connection and firewall settings.

## License

MIT License

---

**Author:** Saumya Talati
**GitHub:** [talati09](https://github.com/talati09)
