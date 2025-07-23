/* See LICENSE file for copyright and license details. */
#define PROJECT_NAME "Prometheus"
#define VERSION      "0.1"

/* maximum limit for package resources */
#define DEPENDS_MAX  20  /* number of depends entries for a package */
#define OUTS_MAX     50  /* number of outs entries for a package */
#define PACKAGES_MAX 500 /* number of packages in a repo */
#define PROGRAM_MAX  20  /* length of package names and program names */
#define REQUIRES_MAX 10  /* number of requires entries for a package */
#define SOURCES_MAX  100 /* number of sources entries for a package */

#define PACKAGE_REPOSITORY "/opt/prometheus" /* the package repository */
#define DEFAULT_PREFIX     "/"               /* the default prefix */
