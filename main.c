#include <assert.h>
#include <ctype.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// -- crypto logic
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block[64];
    size_t i, j;
    uint64_t bits = len * 8;
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint8_t *padded = calloc(padded_len, 1);
    memcpy(padded, data, len);
    padded[len] = 0x80;
    for (i = 0; i < 8; i++)
        padded[padded_len - 8 + i] = (bits >> (56 - i * 8)) & 0xff;

    // Process each 64-byte block
    for (i = 0; i < padded_len; i += 64) {
        uint32_t w[64], a, b, c, d, e, f, g, h0, t1, t2;
        memcpy(block, padded + i, 64);
        for (j = 0; j < 16; j++)
            w[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
                   (block[j * 4 + 2] << 8) | block[j * 4 + 3];
        for (j = 16; j < 64; j++)
            w[j] = sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];

        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        h0 = h[7];

        for (j = 0; j < 64; j++) {
            t1 = h0 + SIG1(e) + CH(e, f, g) + K[j] + w[j];
            t2 = SIG0(a) + MAJ(a, b, c);
            h0 = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h0;
    }

    for (i = 0; i < 8; i++) {
        hash[i * 4] = (h[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (h[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (h[i] >> 8) & 0xff;
        hash[i * 4 + 3] = h[i] & 0xff;
    }
    free(padded);
}

// -- GOL logic
#define TAG_MASK (((1 << 8) - 1) << 16)
#define GENC_MASK (((1 << 8) - 1) << 8)
#define SUM_MASK (((1 << 8) - 1) << 0)

#define ELEM_TAG(e) ((e) & TAG_MASK)
#define ELEM_GENC(e) ((e) & GENC_MASK)
#define ELEM_SUM(e) ((e) & SUM_MASK)
#define ELEM_NO_TAG(e) ((e) & (GENC_MASK | SUM_MASK))
#define ELEM_NO_GENC(e) ((e) & (TAG_MASK | SUM_MASK))

#define MAKE_TAG(t) ((t) << 16)
#define MAKE_GENC(r) ((r) << 8)
#define MAKE_SUM(s) ((s) << 0)

#define NO_ELEM MAKE_TAG(0)
#define BORN_ELEM MAKE_TAG(1)
#define ELEM MAKE_TAG(2)
#define DEAD_ELEM MAKE_TAG(3)

typedef unsigned int cell_t;

typedef struct {
    cell_t **data;
    int width;
    int height;
} grid_t;

// Allocate a new grid
grid_t *create_grid(int width, int height) {
    grid_t *grid = malloc(sizeof(grid_t));
    grid->width = width;
    grid->height = height;
    grid->data = malloc(width * sizeof(cell_t *));
    for (int i = 0; i < width; i++) {
        grid->data[i] = malloc(height * sizeof(cell_t));
    }
    return grid;
}

void free_grid(grid_t *grid) {
    for (int i = 0; i < grid->width; i++) {
        free(grid->data[i]);
    }
    free(grid->data);
    free(grid);
}

static bool random_genc(cell_t e) {
    int g = (ELEM_GENC(e) >> 8);
    return (rand() % 3) < g;
}

static void choose_genc(cell_t e, int *rp) {
    if (ELEM_TAG(e) >= ELEM && random_genc(e))
        (*rp)++;
}

static int baby_genc(grid_t *grid, int i, int j) {
    int jm1 = (j > 0) ? j - 1 : grid->height - 1,
        jp1 = (j < grid->height - 1) ? j + 1 : 0,
        im1 = (i > 0) ? i - 1 : grid->width - 1,
        ip1 = (i < grid->width - 1) ? i + 1 : 0, r = 0;
    choose_genc(grid->data[im1][jm1], &r);
    choose_genc(grid->data[im1][j], &r);
    choose_genc(grid->data[im1][jp1], &r);
    choose_genc(grid->data[i][jm1], &r);
    choose_genc(grid->data[i][jp1], &r);
    choose_genc(grid->data[ip1][jm1], &r);
    choose_genc(grid->data[ip1][j], &r);
    choose_genc(grid->data[ip1][jp1], &r);
    return MAKE_GENC(r);
}

int one_step(grid_t *grid) {
    int modif = 0;
    cell_t r;

    for (int i = 0; i < grid->width; i++) {
        for (int j = 0; j < grid->height; j++) {
            cell_t e = grid->data[i][j];
            switch (ELEM_SUM(e)) {
            case MAKE_SUM(3):
                if (ELEM_TAG(e) == NO_ELEM) {
                    r = baby_genc(grid, i, j);
                    r = r | ELEM_SUM(e);
                    grid->data[i][j] = BORN_ELEM | r;
                    modif = 1;
                }
                break;
            case MAKE_SUM(0):
            case MAKE_SUM(1):
            case MAKE_SUM(4):
            case MAKE_SUM(5):
            case MAKE_SUM(6):
            case MAKE_SUM(7):
            case MAKE_SUM(8):
                if (ELEM_TAG(e) == ELEM) {
                    r = ELEM_NO_TAG(e);
                    grid->data[i][j] = DEAD_ELEM | r;
                    modif = 1;
                }
                break;
            }
        }
    }
    return modif;
}

int update(grid_t *grid) {
    int modif = 0;
    cell_t r;

    for (int i = 0; i < grid->width; i++) {
        int im1 = (i > 0) ? i - 1 : grid->width - 1;
        int ip1 = (i < grid->width - 1) ? i + 1 : 0;

        for (int j = 0; j < grid->height; j++) {
            int jm1 = (j > 0) ? j - 1 : grid->height - 1;
            int jp1 = (j < grid->height - 1) ? j + 1 : 0;

            switch (ELEM_TAG(grid->data[i][j])) {
            case BORN_ELEM:
                r = ELEM_NO_TAG(grid->data[i][j]);
                grid->data[im1][jm1] += 1;
                grid->data[im1][j] += 1;
                grid->data[im1][jp1] += 1;
                grid->data[i][jm1] += 1;
                grid->data[i][j] = ELEM | r;
                grid->data[i][jp1] += 1;
                grid->data[ip1][jm1] += 1;
                grid->data[ip1][j] += 1;
                grid->data[ip1][jp1] += 1;
                modif = 1;
                break;
            case DEAD_ELEM:
                r = ELEM_NO_TAG(grid->data[i][j]);
                grid->data[im1][jm1] -= 1;
                grid->data[im1][j] -= 1;
                grid->data[im1][jp1] -= 1;
                grid->data[i][jm1] -= 1;
                grid->data[i][j] = NO_ELEM | r;
                grid->data[i][jp1] -= 1;
                grid->data[ip1][jm1] -= 1;
                grid->data[ip1][j] -= 1;
                grid->data[ip1][jp1] -= 1;
                modif = 1;
                break;
            }
        }
    }
    return modif;
}

void fill(grid_t *grid, cell_t value) {
    for (int i = 0; i < grid->width; i++) {
        for (int j = 0; j < grid->height; j++) {
            grid->data[i][j] = value;
        }
    }
}

void print_grid(grid_t *grid) {
    for (int j = 0; j < grid->height; j++) {
        for (int i = 0; i < grid->width; i++) {
            cell_t cell = grid->data[i][j];
            char symbol;

            switch (ELEM_TAG(cell)) {
            case NO_ELEM:
                symbol = '.';
                break; // Empty cell
            case BORN_ELEM:
                symbol = '+';
                break; // Newly born cell
            case ELEM:
                symbol = 'O';
                break; // Living cell
            case DEAD_ELEM:
                symbol = 'x';
                break; // Dying cell
            }
            printf("%c ", symbol);
        }
        printf("\n");
    }
    printf("\n");
}

void init_grid_from_string(grid_t *grid, const char *str) {
    uint8_t hash[32];
    sha256((const uint8_t *)str, strlen(str), hash);
    // Use first 4 bytes of hash as seed
    uint32_t seed =
        (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    srand(seed);

    // Fill grid with random alive/dead states based on hash
    for (int i = 0; i < grid->width; i++) {
        for (int j = 0; j < grid->height; j++) {
            // Use next bit from hash-like random sequence
            int bit = rand() % 2;
            grid->data[i][j] = bit ? ELEM : NO_ELEM;
            // Initialize neighbor count to 0; will be updated later
            grid->data[i][j] &= ~SUM_MASK;
        }
    }

    // Update neighbor counts
    for (int i = 0; i < grid->width; i++) {
        for (int j = 0; j < grid->height; j++) {
            if (ELEM_TAG(grid->data[i][j]) == ELEM) {
                int im1 = (i > 0) ? i - 1 : grid->width - 1;
                int ip1 = (i < grid->width - 1) ? i + 1 : 0;
                int jm1 = (j > 0) ? j - 1 : grid->height - 1;
                int jp1 = (j < grid->height - 1) ? j + 1 : 0;
                grid->data[im1][jm1] += 1;
                grid->data[im1][j] += 1;
                grid->data[im1][jp1] += 1;
                grid->data[i][jm1] += 1;
                grid->data[i][jp1] += 1;
                grid->data[ip1][jm1] += 1;
                grid->data[ip1][j] += 1;
                grid->data[ip1][jp1] += 1;
            }
        }
    }
}

// NCurses TUI
#define GRID_WIDTH 30
#define GRID_HEIGHT 20
// thanks https://www.linuxjournal.com/content/programming-color-ncurses
#define COLOR_NO_ELEM 1
#define COLOR_BORN_ELEM 2
#define COLOR_ELEM 3
#define COLOR_DEAD_ELEM 4


void toggle_cell(grid_t *grid, int x, int y) {
    int im1 = (x > 0) ? x - 1 : grid->width - 1;
    int ip1 = (x < grid->width - 1) ? x + 1 : 0;
    int jm1 = (y > 0) ? y - 1 : grid->height - 1;
    int jp1 = (y < grid->height - 1) ? y + 1 : 0;

    if (ELEM_TAG(grid->data[x][y]) == NO_ELEM) {
        grid->data[x][y] = ELEM | (grid->data[x][y] & ~TAG_MASK);
        grid->data[im1][jm1] += 1;
        grid->data[im1][y] += 1;
        grid->data[im1][jp1] += 1;
        grid->data[x][jm1] += 1;
        grid->data[x][jp1] += 1;
        grid->data[ip1][jm1] += 1;
        grid->data[ip1][y] += 1;
        grid->data[ip1][jp1] += 1;
    } else if (ELEM_TAG(grid->data[x][y]) == ELEM) {
        grid->data[x][y] = NO_ELEM | (grid->data[x][y] & ~TAG_MASK);
        grid->data[im1][jm1] -= 1;
        grid->data[im1][y] -= 1;
        grid->data[im1][jp1] -= 1;
        grid->data[x][jm1] -= 1;
        grid->data[x][jp1] -= 1;
        grid->data[ip1][jm1] -= 1;
        grid->data[ip1][y] -= 1;
        grid->data[ip1][jp1] -= 1;
    }
}

void draw_grid(WINDOW *win, grid_t *grid, int step, int cursor_x,
               int cursor_y) {
    int unknown_count = 0;
    werase(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 2, "Cellular Automaton - Step %d", step);

    for (int j = 0; j < GRID_HEIGHT; j++) {
        for (int i = 0; i < GRID_WIDTH; i++) {
            cell_t cell = grid->data[i][j];
            char symbol;
            int color_pair;
            switch (ELEM_TAG(cell)) {
            case NO_ELEM:
                symbol = '.';
                color_pair = COLOR_NO_ELEM;
                break;
            case BORN_ELEM:
                symbol = '+';
                color_pair = COLOR_BORN_ELEM;
                break;
            case ELEM:
                symbol = 'O';
                color_pair = COLOR_ELEM;
                break;
            case DEAD_ELEM:
                symbol = 'x';
                color_pair = COLOR_DEAD_ELEM;
                break;
            }
            if (i == cursor_x && j == cursor_y) {
                wattron(win, A_REVERSE);
            }
            wattron(win, COLOR_PAIR(color_pair));
            mvwprintw(win, j + 1, i * 2 + 1, "%c ", symbol);
            wattroff(win, COLOR_PAIR(color_pair));
            if (i == cursor_x && j == cursor_y) {
                wattroff(win, A_REVERSE);
            }
        }
    }
    wrefresh(win);
}

void draw_menu(WINDOW *menu_win, const char *seed, int cursor_pos) {
    werase(menu_win);
    box(menu_win, 0, 0);
    mvwprintw(menu_win, 0, 2, "Seed Input");
    mvwprintw(menu_win, 1, 1, "Seed: %s", seed);
    mvwprintw(menu_win, 2, 1, "[Enter]: step, [-]: reset, [+]: toggle_cell, [<TAB>]: quit");
    wmove(menu_win, 1, 6 + cursor_pos); // Cursor position in seed
    wrefresh(menu_win);
}

void draw_hash(WINDOW *hash_win, const char *seed) {
    werase(hash_win);
    box(hash_win, 0, 0);
    mvwprintw(hash_win, 0, 2, "SHA-256 Hash");
    uint8_t hash[32];
    sha256((const uint8_t *)seed, strlen(seed), hash);
    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_str + i * 2, "%02x", hash[i]);
    }
    hash_str[64] = '\0';
    mvwprintw(hash_win, 1, 15, "%.32s", hash_str);      // First 32 chars
    mvwprintw(hash_win, 2, 15, "%.32s", hash_str + 32); // Last 32 chars
    wrefresh(hash_win);
}

void draw_counts(WINDOW *counts_win, grid_t *grid) {
    werase(counts_win);
    box(counts_win, 0, 0);
    mvwprintw(counts_win, 0, 2, "Cell Counts");
    int no_elem = 0, born_elem = 0, elem = 0, dead_elem = 0;
    for (int i = 0; i < GRID_WIDTH; i++) {
        for (int j = 0; j < GRID_HEIGHT; j++) {
            switch (ELEM_TAG(grid->data[i][j])) {
            case NO_ELEM:
                no_elem++;
                break;
            case BORN_ELEM:
                born_elem++;
                break;
            case ELEM:
                elem++;
                break;
            case DEAD_ELEM:
                dead_elem++;
                break;
            }
        }
    }
    mvwprintw(counts_win, 1, 1, "Empty: %d", no_elem);
    mvwprintw(counts_win, 2, 1, "Born:  %d", born_elem);
    mvwprintw(counts_win, 3, 1, "Alive: %d", elem);
    mvwprintw(counts_win, 4, 1, "Dead:  %d", dead_elem);
    wrefresh(counts_win);
}

void run_tui() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    if (has_colors() == FALSE) {
        endwin();
        printf("Your terminal does not support color\n");
        return;
    }
    start_color();
    //init_pair(COLOR_NO_ELEM, COLOR_WHITE, COLOR_BLACK);
	//init_color(COLOR_GREEN, 0, 255, 0);
    init_pair(COLOR_BORN_ELEM, COLOR_GREEN, COLOR_BLACK);
	init_color(COLOR_BLACK, 0, 0, 0);
    init_pair(COLOR_ELEM, COLOR_BLUE, COLOR_BLACK);
    init_pair(COLOR_DEAD_ELEM, COLOR_RED, COLOR_BLACK);
    bkgd(COLOR_PAIR(COLOR_NO_ELEM));
    /**/
    /*// Check terminal size*/
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
	/*
    if (max_y < GRID_HEIGHT + 5 || max_x < GRID_WIDTH * 2 + 2) {
        endwin();
        printf("Terminal too small. Minimum size: %dx%d\n", GRID_WIDTH * 2 + 2,
               GRID_HEIGHT + 5);
        return;
    }
	*/

    // Calculate centered positions
    int grid_start_y = (max_y - (GRID_HEIGHT + 2 + 4)) / 2;
    int grid_start_x = (max_x - (GRID_WIDTH * 2 + 2)) / 2;
    int counts_start_x = grid_start_x + GRID_WIDTH * 2 + 2;
    int menu_start_y = grid_start_y + GRID_HEIGHT + 2;
    int hash_start_y = menu_start_y + 4;

    // Create windows
    WINDOW *grid_win =
        newwin(GRID_HEIGHT + 2, GRID_WIDTH * 2 + 2, grid_start_y, grid_start_x);
    WINDOW *menu_win =
        newwin(4, GRID_WIDTH * 2 + 2, menu_start_y, grid_start_x);
    WINDOW *hash_win =
        newwin(4, GRID_WIDTH * 2 + 2, hash_start_y, grid_start_x);
    WINDOW *counts_win = newwin(6, 22, grid_start_y, counts_start_x);

    // Initialize grid
    grid_t *grid = create_grid(GRID_WIDTH, GRID_HEIGHT);
    char seed[256] = "";
    init_grid_from_string(grid, seed);

    int step = 0;
    int cursor_pos = strlen(seed);
    bool running = true;
    int cursor_x = 0, cursor_y = 0;
    draw_grid(grid_win, grid, step, cursor_x, cursor_y);
    draw_menu(menu_win, seed, cursor_pos);
    draw_hash(hash_win, seed);
    draw_counts(counts_win, grid);

    while (running) {
        int ch = getch();
        switch (ch) {
        case '\t': // Quit
            running = false;
            break;
        case '\n': // Step
            one_step(grid);
            update(grid);
            step++;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
			draw_counts(counts_win, grid);
            break;
        case KEY_UP:
            if (cursor_y > 0)
                cursor_y--;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            break;
        case KEY_DOWN:
            if (cursor_y < GRID_HEIGHT - 1)
                cursor_y++;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            break;
        case KEY_LEFT:
            if (cursor_x > 0)
                cursor_x--;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            break;
        case KEY_RIGHT:
            if (cursor_x < GRID_WIDTH - 1)
                cursor_x++;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            break;
        case '-': // Reset
			init: init_grid_from_string(grid, seed);
            step = 0;
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            draw_hash(hash_win, seed);
            draw_counts(counts_win, grid);
            break;
        case KEY_BACKSPACE: // Delete     Delete character
            if (cursor_pos > 0) {
                seed[--cursor_pos] = '\0';
				goto menu;
            }
            break;
        case '+':
            toggle_cell(grid, cursor_x, cursor_y);
            draw_grid(grid_win, grid, step, cursor_x, cursor_y);
            draw_counts(counts_win, grid);
            break;

        default: // Add character to seed
            if (cursor_pos < 255 && isprint(ch)) {
                seed[cursor_pos++] = ch;
                seed[cursor_pos] = '\0';
				menu: draw_menu(menu_win, seed, cursor_pos);
				draw_hash(hash_win, seed);
				goto init;
            }
            break;
        }
    }

    free_grid(grid);
    delwin(grid_win);
    delwin(menu_win);
    delwin(hash_win);
    delwin(counts_win);
    endwin();
}

int main(int argc, char *argv[]) {
    run_tui();
    // need to test
    return 0;
}
