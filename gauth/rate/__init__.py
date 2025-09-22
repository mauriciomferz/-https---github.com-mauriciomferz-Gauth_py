"""
GAuth Rate Limiting Package

Comprehensive rate limiting implementation with support for multiple algorithms,
distributed backends, and HTTP middleware integration.
"""

from .limiter import (
    RateLimiter,
    RateLimitConfig,
    RateLimitQuota,
    RateLimitError,
    RateLimitExceeded,
    InvalidConfigError,
    TokenBucketLimiter,
    SlidingWindowLimiter,
    FixedWindowLimiter,
    create_rate_limiter,
    create_token_bucket_limiter,
    create_sliding_window_limiter,
    create_fixed_window_limiter
)

from .redis_limiter import (
    RedisRateLimiter,
    RedisTokenBucketLimiter,
    RedisSlidingWindowLimiter,
    RedisFixedWindowLimiter,
    create_redis_rate_limiter,
    create_redis_token_bucket,
    create_redis_sliding_window,
    create_redis_fixed_window
)

from .middleware import (
    RateLimitMiddleware,
    AioHttpRateLimitMiddleware,
    FastAPIRateLimitMiddleware,
    FlaskRateLimitMiddleware,
    rate_limit,
    create_aiohttp_rate_limit_middleware,
    create_fastapi_rate_limit_middleware,
    create_flask_rate_limit_middleware
)


__all__ = [
    # Core rate limiting
    'RateLimiter',
    'RateLimitConfig',
    'RateLimitQuota',
    'RateLimitError',
    'RateLimitExceeded',
    'InvalidConfigError',
    
    # Memory-based limiters
    'TokenBucketLimiter',
    'SlidingWindowLimiter',
    'FixedWindowLimiter',
    'create_rate_limiter',
    'create_token_bucket_limiter',
    'create_sliding_window_limiter',
    'create_fixed_window_limiter',
    
    # Redis-based limiters
    'RedisRateLimiter',
    'RedisTokenBucketLimiter',
    'RedisSlidingWindowLimiter',
    'RedisFixedWindowLimiter',
    'create_redis_rate_limiter',
    'create_redis_token_bucket',
    'create_redis_sliding_window',
    'create_redis_fixed_window',
    
    # HTTP middleware
    'RateLimitMiddleware',
    'AioHttpRateLimitMiddleware',
    'FastAPIRateLimitMiddleware',
    'FlaskRateLimitMiddleware',
    'rate_limit',
    'create_aiohttp_rate_limit_middleware',
    'create_fastapi_rate_limit_middleware',
    'create_flask_rate_limit_middleware'
]


# Package metadata
__version__ = '1.0.0'
__author__ = 'GAuth Team'
__description__ = 'Comprehensive rate limiting for GAuth applications'