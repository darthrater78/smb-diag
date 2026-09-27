/* Stand-in for a Windows tool (klist.exe, dsregcmd.exe) inside the throwaway Wine prefix.
   Prints %SHOTS_FAKE_DIR%\<own name>.txt, which Shots.cs writes with mock output, so the
   app's own parsing and rendering run unchanged. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main(void)
{
    char self[MAX_PATH], path[MAX_PATH * 2], buf[4096];
    const char *dir = getenv("SHOTS_FAKE_DIR");
    if (!dir || !GetModuleFileNameA(NULL, self, MAX_PATH)) return 1;

    char *name = strrchr(self, '\\');
    name = name ? name + 1 : self;
    char *ext = strrchr(name, '.');
    if (ext) *ext = '\0';

    snprintf(path, sizeof path, "%s\\%s.txt", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}
