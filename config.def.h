/* See LICENSE file for copyright and license details. */
#define PROJECTNAME "Prometheus"
#define VERSION     "0.1"

/* maximum limit for package resources */
#define DEPENDS_MAX  20
#define OUTS_MAX     50
#define PROGRAM_MAX  20 /* it also applies to package names */
#define REQUIRES_MAX 10
#define SOURCES_MAX  100

/* the directory containing the package repository */
static char *const pkgsrepodir = "/opt/olympus";
/* check README for more informations about package repositories */

/* the default prefix for installing packages */
static char *const defaultprefix = "/";
