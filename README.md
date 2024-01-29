# SSH Log Analyzer

This is a simple Go-based project for parsing and analyzing SSH logs to identify and analyze failed login attempts. The project includes features like time-based analysis, filtering by username and IP address, and provides a summary of failed login attempts.

## Project Structure

The project follows the standard Go project structure:

- **main.go**: The main entry point of the application.
- **parsing/parsing.go**: Handles the parsing logic for SSH logs.
- **analysis/analysis.go**: Contains the analysis and summary printing logic.

## Usage

### Command-line Flags

- `-log`: Path to the SSH log file (default: `/var/log/auth.log`).
- `-user`: Filter results by username.
- `-ip`: Filter results by IP address.
- `-time`: Time range for analysis (e.g., `1h`, `24h`).

### Running the Application

To run the application, use the following command:

```bash
go run main.go -log /path/to/your/auth.log -user <username> -ip <ip_address> -time 24h
```
## Contributing
Feel free to contribute to the project by opening issues or submitting pull requests.

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
