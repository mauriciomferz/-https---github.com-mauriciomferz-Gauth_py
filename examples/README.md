# GAuth Python Examples

This directory contains examples demonstrating various GAuth features and usage patterns.

## Examples

### Basic Usage (`basic_usage.py`)
Demonstrates the fundamental GAuth operations:
- Creating a GAuth instance
- Authorization flow
- Token management
- Transaction processing

```bash
python examples/basic_usage.py
```

### Advanced Features (`advanced_features.py`)
Shows advanced GAuth capabilities:
- Custom audit logging to files
- Rate limiting configuration
- Token restrictions
- Error handling patterns

```bash
python examples/advanced_features.py
```

### Running Examples

To run the examples, make sure you have installed the GAuth Python package:

```bash
# Install in development mode
pip install -e .

# Or install from PyPI (when published)
pip install gauth-py
```

Then run any example:

```bash
python examples/basic_usage.py
python examples/advanced_features.py
```

## Example Structure

Each example is self-contained and demonstrates specific aspects of the GAuth protocol:

- **Configuration**: How to set up GAuth with different options
- **Authorization**: Requesting and granting permissions
- **Tokens**: Issuing, validating, and managing access tokens
- **Transactions**: Processing operations with proper authorization
- **Audit**: Logging and retrieving audit events
- **Error Handling**: Graceful handling of various error conditions

## Customization

The examples can be modified to test different scenarios:

- Change token expiry times
- Modify scopes and permissions
- Add custom restrictions
- Implement different audit logging strategies
- Test rate limiting behavior

## Production Considerations

When adapting these examples for production use, consider:

- Using persistent storage (Redis, database) instead of in-memory stores
- Implementing proper secret management
- Adding comprehensive error handling and monitoring
- Configuring appropriate rate limits and timeouts
- Setting up proper audit log storage and retention