/*
 * compat_else_check - every preprocessor conditional must have a default.
 *
 * px-fuse supports a wide range of kernels and distros purely through
 * preprocessor conditionals.  A conditional with no #else silently compiles to
 * nothing on every kernel that matches none of its branches:
 *
 *	#if   LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,25) || ...
 *		blk_mark_disk_dead(pxd_dev->disk);
 *	#elif LINUX_VERSION_CODE <  KERNEL_VERSION(5,13,0)
 *		blk_set_queue_dying(pxd_dev->disk->queue);
 *	#endif
 *
 * The build stays green and the behaviour just disappears - here on every
 * 5.13/5.14 kernel.  This checker reports every #if/#ifdef/#ifndef that reaches
 * its #endif without an #else, whatever the conditions are and however many
 * #elif branches it has.  No kernel version, distro or -D flag knowledge is
 * involved: if a conditional has a default branch it passes, otherwise it does
 * not.
 *
 * The one exception is a file's include guard, which by construction cannot
 * have an #else.
 *
 * Build and run (no dependencies beyond a C compiler):
 *	gcc -Wall -Wextra -std=c99 -o test/compat_else_check test/compat_else_check.c
 *	./test/compat_else_check              # every *.c and *.h in the current dir
 *	./test/compat_else_check pxd.c pxd.h  # or an explicit list
 *	./test/compat_else_check -w           # report but always exit 0
 *
 * Exit status: 0 = every conditional has a default, 1 = some do not,
 * 2 = usage or I/O error.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64
#define MAX_LINE 8192
#define MAX_COND 200
#define MAX_FILES 512
#define MAX_NAME 128
#define MAX_VIOL 512

struct cond_block {
	int line;		/* line of the #if				*/
	int has_else;		/* an #else was seen				*/
	int nelif;		/* how many #elif branches			*/
	int is_guard;		/* this is the file's include guard		*/
	int endif_line;		/* line of the matching #endif			*/
	char cond[MAX_COND];	/* condition text, for the report		*/
};

static int opt_warn_only;
static int opt_quiet;

/*
 * Copy `in` to `out` with comments removed, so that directives commented out
 * are not mistaken for real ones.  *in_comment carries block comment state
 * across lines.  String and character literals are skipped over so a comment
 * opener inside them is left alone.
 */
static void strip_comments(const char *in, char *out, size_t outsz, int *in_comment)
{
	size_t o = 0;

	for (size_t i = 0; in[i] != '\0' && o + 1 < outsz; ) {
		if (*in_comment) {
			if (in[i] == '*' && in[i + 1] == '/') {
				*in_comment = 0;
				i += 2;
			} else {
				i++;
			}
			continue;
		}
		if (in[i] == '/' && in[i + 1] == '*') {
			*in_comment = 1;
			out[o++] = ' ';
			i += 2;
			continue;
		}
		if (in[i] == '/' && in[i + 1] == '/')
			break;
		if (in[i] == '"' || in[i] == '\'') {
			char quote = in[i];

			out[o++] = in[i++];
			while (in[i] != '\0' && o + 1 < outsz) {
				if (in[i] == '\\' && in[i + 1] != '\0') {
					out[o++] = in[i++];
					if (o + 1 < outsz)
						out[o++] = in[i++];
					continue;
				}
				out[o++] = in[i];
				if (in[i++] == quote)
					break;
			}
			continue;
		}
		out[o++] = in[i++];
	}
	out[o] = '\0';
}

/*
 * If `line` is a preprocessor conditional directive, return its keyword and
 * point `*rest` at whatever follows it.  Returns NULL otherwise.
 */
static const char *directive(const char *line, const char **rest)
{
	static const char *const keywords[] = {
		"ifdef", "ifndef", "if", "elifdef", "elifndef", "elif", "else", "endif",
	};
	const char *p = line;

	while (isspace((unsigned char)*p))
		p++;
	if (*p != '#')
		return NULL;
	p++;
	while (isspace((unsigned char)*p))
		p++;

	for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
		size_t len = strlen(keywords[i]);

		if (strncmp(p, keywords[i], len) == 0 &&
		    (p[len] == '\0' || isspace((unsigned char)p[len]))) {
			const char *r = p + len;

			while (isspace((unsigned char)*r))
				r++;
			*rest = r;
			return keywords[i];
		}
	}
	return NULL;
}

/* First identifier in `s`, for matching an include guard's #ifndef/#define. */
static void first_identifier(const char *s, char *out, size_t outsz)
{
	size_t o = 0;

	while (isspace((unsigned char)*s))
		s++;
	while ((isalnum((unsigned char)*s) || *s == '_') && o + 1 < outsz)
		out[o++] = *s++;
	out[o] = '\0';
}

/* Collapse runs of whitespace and clip, so long conditions stay readable. */
static void summarize(const char *s, char *out, size_t outsz)
{
	size_t o = 0;
	int space = 0;

	while (*s != '\0' && o + 1 < outsz) {
		if (isspace((unsigned char)*s)) {
			space = 1;
			s++;
			continue;
		}
		if (space && o + 1 < outsz)
			out[o++] = ' ';
		space = 0;
		if (o + 1 < outsz)
			out[o++] = *s++;
	}
	out[o] = '\0';
	if (o + 1 >= outsz && o >= 3)
		strcpy(out + o - 3, "...");
}

/* Conditionals are popped innermost first; report them in source order. */
static int compare_blocks(const void *a, const void *b)
{
	const struct cond_block *x = a, *y = b;

	return x->line - y->line;
}

static int check_file(const char *path, int *violations)
{
	FILE *fh = fopen(path, "r");
	struct cond_block stack[MAX_DEPTH];
	struct cond_block found[MAX_VIOL];
	int nfound = 0;
	char raw[MAX_LINE], joined[MAX_LINE], clean[MAX_LINE];
	char guard_name[MAX_NAME] = "";
	int depth = 0, lineno = 0, in_comment = 0;
	int seen_directive = 0, guard_pending = 0;
	int failed = 0;

	if (fh == NULL) {
		fprintf(stderr, "%s: cannot open file\n", path);
		return -1;
	}

	while (fgets(raw, sizeof(raw), fh) != NULL) {
		const char *rest = NULL, *kw = NULL;
		int start_line = ++lineno;
		size_t len;

		/* join backslash continuations so a condition stays in one piece */
		snprintf(joined, sizeof(joined), "%s", raw);
		len = strlen(joined);
		while (len > 0 && (joined[len - 1] == '\n' || joined[len - 1] == '\r'))
			joined[--len] = '\0';
		while (len > 0 && joined[len - 1] == '\\') {
			joined[--len] = '\0';
			if (fgets(raw, sizeof(raw), fh) == NULL)
				break;
			lineno++;
			snprintf(joined + len, sizeof(joined) - len, "%s", raw);
			len = strlen(joined);
			while (len > 0 && (joined[len - 1] == '\n' || joined[len - 1] == '\r'))
				joined[--len] = '\0';
		}

		strip_comments(joined, clean, sizeof(clean), &in_comment);
		kw = directive(clean, &rest);

		/* an include guard is "#ifndef NAME" immediately followed by "#define NAME" */
		if (guard_pending) {
			const char *p = clean;
			char name[MAX_NAME];

			while (isspace((unsigned char)*p))
				p++;
			if (*p == '#') {
				p++;
				while (isspace((unsigned char)*p))
					p++;
				if (strncmp(p, "define", 6) == 0) {
					first_identifier(p + 6, name, sizeof(name));
					if (strcmp(name, guard_name) == 0 && depth > 0)
						stack[depth - 1].is_guard = 1;
				}
			}
			if (*p != '\0')
				guard_pending = 0;
		}

		if (kw == NULL)
			continue;

		if (strcmp(kw, "if") == 0 || strcmp(kw, "ifdef") == 0 ||
		    strcmp(kw, "ifndef") == 0) {
			if (depth >= MAX_DEPTH) {
				fprintf(stderr, "%s:%d: nesting too deep\n", path, start_line);
				fclose(fh);
				return -1;
			}
			stack[depth].line = start_line;
			stack[depth].has_else = 0;
			stack[depth].nelif = 0;
			stack[depth].is_guard = 0;
			summarize(clean, stack[depth].cond, sizeof(stack[depth].cond));
			depth++;

			if (!seen_directive && depth == 1 && strcmp(kw, "ifndef") == 0) {
				first_identifier(rest, guard_name, sizeof(guard_name));
				guard_pending = guard_name[0] != '\0';
			}
			seen_directive = 1;
		} else if (strcmp(kw, "elif") == 0 || strcmp(kw, "elifdef") == 0 ||
			   strcmp(kw, "elifndef") == 0) {
			if (depth == 0) {
				fprintf(stderr, "%s:%d: #%s without #if\n", path, start_line, kw);
				fclose(fh);
				return -1;
			}
			stack[depth - 1].nelif++;
			seen_directive = 1;
		} else if (strcmp(kw, "else") == 0) {
			if (depth == 0) {
				fprintf(stderr, "%s:%d: #else without #if\n", path, start_line);
				fclose(fh);
				return -1;
			}
			stack[depth - 1].has_else = 1;
			seen_directive = 1;
		} else { /* endif */
			struct cond_block *b;

			if (depth == 0) {
				fprintf(stderr, "%s:%d: #endif without #if\n", path, start_line);
				fclose(fh);
				return -1;
			}
			b = &stack[--depth];
			seen_directive = 1;
			if (b->has_else || b->is_guard)
				continue;

			(*violations)++;
			failed = 1;
			if (!opt_quiet && nfound < MAX_VIOL) {
				found[nfound] = *b;
				found[nfound].endif_line = start_line;
				nfound++;
			}
		}
	}

	if (depth != 0) {
		fprintf(stderr, "%s: %d unterminated #if (starting at line %d)\n",
			path, depth, stack[0].line);
		fclose(fh);
		return -1;
	}
	fclose(fh);

	qsort(found, (size_t)nfound, sizeof(found[0]), compare_blocks);
	for (int i = 0; i < nfound; i++) {
		printf("%s:%d: no #else (%s", path, found[i].line, found[i].cond);
		if (found[i].nelif > 0)
			printf(", %d #elif", found[i].nelif);
		printf(", #endif at line %d)\n", found[i].endif_line);
	}
	return failed;
}

static int is_source(const char *name)
{
	size_t len = strlen(name);

	if (len < 3 || name[len - 2] != '.')
		return 0;
	if (name[len - 1] != 'c' && name[len - 1] != 'h')
		return 0;
	/* generated during the build, not checked in */
	if (strcmp(name, "px.mod.c") == 0 || strcmp(name, "px_version.c") == 0 ||
	    strcmp(name, "config.h") == 0 || strcmp(name, "config.h.in") == 0)
		return 0;
	return 1;
}

static int compare_names(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Default target list: every driver source in the current directory. */
static int collect_sources(char **files, int max)
{
	DIR *dir = opendir(".");
	struct dirent *ent;
	int n = 0;

	if (dir == NULL) {
		fprintf(stderr, "cannot read current directory\n");
		return -1;
	}
	while ((ent = readdir(dir)) != NULL && n < max) {
		if (!is_source(ent->d_name))
			continue;
		files[n] = strdup(ent->d_name);
		if (files[n] == NULL) {
			closedir(dir);
			return -1;
		}
		n++;
	}
	closedir(dir);
	qsort(files, (size_t)n, sizeof(files[0]), compare_names);
	return n;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [-w] [-q] [file ...]\n"
		"  every #if/#ifdef/#ifndef must have an #else before its #endif\n"
		"  -w  report violations but exit 0\n"
		"  -q  print only the summary\n"
		"  no files given: all *.c and *.h in the current directory\n",
		argv0);
}

int main(int argc, char **argv)
{
	char *owned[MAX_FILES];
	char **files;
	int nfiles = 0, nowned = 0, violations = 0, bad_files = 0, i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-w") == 0) {
			opt_warn_only = 1;
		} else if (strcmp(argv[i], "-q") == 0) {
			opt_quiet = 1;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 2;
		} else {
			break;
		}
	}

	if (i < argc) {
		files = &argv[i];
		nfiles = argc - i;
	} else {
		nowned = collect_sources(owned, MAX_FILES);
		if (nowned < 0)
			return 2;
		files = owned;
		nfiles = nowned;
	}

	if (nfiles == 0) {
		fprintf(stderr, "no source files to check\n");
		return 2;
	}

	for (i = 0; i < nfiles; i++) {
		int ret = check_file(files[i], &violations);

		if (ret < 0)
			bad_files++;
	}

	printf("%d conditional%s without #else in %d file%s checked\n",
	       violations, violations == 1 ? "" : "s",
	       nfiles, nfiles == 1 ? "" : "s");

	for (i = 0; i < nowned; i++)
		free(owned[i]);

	if (bad_files > 0)
		return 2;
	if (violations > 0 && !opt_warn_only)
		return 1;
	return 0;
}
