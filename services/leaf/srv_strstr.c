
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

char *leaf_strstr(const char *haystack, const char *needle)
{
    if (!*needle)
        return (char *) haystack;

    const char    needle_first  = *needle;

    haystack = strchr(haystack, needle_first);
    if (!haystack) 
        return NULL;

    const char   *i_haystack = haystack + 1, *i_needle = needle + 1;
    unsigned int  sums_diff = *haystack;
    bool          identical = true;

    while (*i_haystack && *i_needle) {
        sums_diff += *i_haystack;
        sums_diff -= *i_needle;
        identical &= *i_haystack++ == *i_needle++;
    }

    if (*i_needle) 
        return NULL;
    else if (identical)
        return (char *) haystack;

    size_t        needle_len    = i_needle - needle;
    size_t        needle_len_1  = needle_len - 1;

    const char   *sub_start;
    for (sub_start = haystack; *i_haystack; i_haystack++) {
        sums_diff -= *sub_start++;
        sums_diff += *i_haystack;
        if (sums_diff == 0 && needle_first == *sub_start && memcmp(sub_start, needle, needle_len_1) == 0)
            return (char *) sub_start;
    }
    return NULL;
}
