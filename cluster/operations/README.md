# Operations templates

The backup and backup-check CronJobs are suspended templates. They intentionally
use the real, non-production Alpine image pinned to its official Docker Hub
manifest digest and fail closed before any provider upload or integrity claim.
They are not an accepted backup mechanism.

Before enabling them, create an encrypted `backup-credentials` Secret, replace
the scripts with an application-native dump plus encrypted off-cluster upload,
add an egress policy for the selected object-store endpoint, pin the production
image by digest, and complete a disposable restore drill. Then enable both
CronJobs through Git and verify the resulting Job, checksum, age, size, and
restore evidence.
