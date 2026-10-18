#pragma once

// The deployer only reads zip archives and inflates data, so the vendored
// miniz is built without compression and file APIs.
#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
