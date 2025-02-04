// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef LIBCOVERAGE_H
#define LIBCOVERAGE_H

#include <stdint.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <Windows.h>
#endif

// Tracks a set of edges by their indices
struct edge_set {
    uint32_t count;
    uint32_t * edge_indices;
};

// Tracks the hit count of all edges
struct edge_counts {
    uint32_t count;
    uint32_t * edge_hit_count;
};

// Size of the shared memory region. Defines an upper limit on the number of
// coverage edges that can be tracked. When bumping this number, please also
// update Target/coverage.c.
#define SHM_SIZE_FOR_CODE 0x100000
#define SHM_SIZE_FOR_TYPE 0x8000
#define SHM_SIZE_FOR_COVERAGE  128     // 1024 bits = 128 bytes
#define SHM_SIZE (SHM_SIZE_FOR_CODE + SHM_SIZE_FOR_TYPE + SHM_SIZE_FOR_COVERAGE)

#define MAX_EDGES ((SHM_SIZE_FOR_CODE - 4) * 8)

#define COVERAGE_BITS_SIZE 1024
#define LOCATION_BITS_SIZE 512
#define TYPE_BITS_SIZE     512
#define COVERAGE_BYTES_SIZE  (COVERAGE_BITS_SIZE / 8)  // 128
#define LOCATION_BYTES_SIZE  (LOCATION_BITS_SIZE / 8)  // 64
#define TYPE_BYTES_SIZE      (TYPE_BITS_SIZE / 8)      // 64

struct shmem_data {
    uint32_t num_edges;
    // Use the same coverage_bits array as in V8:
    unsigned char coverage_bits[COVERAGE_BYTES_SIZE];  // 1024 bits = 128 bytes

    // The edges bitmap follows immediately after coverage_bits
    unsigned char edges[];
};

struct cov_context {
    // Id of this coverage context.
    int id;
    
    int should_track_edges;

    // Bitmap of edges that have been discovered so far.
    uint8_t* virgin_bits;
    
    // Bitmap of edges that have been discovered in crashing samples so far.
    uint8_t* crash_bits;

    // Total number of edges in the target program.
    uint32_t num_edges;
    
    // Number of used bytes in the shmem->edges bitmap, roughly num_edges / 8.
    uint32_t bitmap_size;
    
    // Total number of edges that have been discovered so far.
    uint32_t found_edges;

    // Total number of edges that have been discovered so far.
    uint32_t found_types;

#if defined(_WIN32)
    // Mapping Handle
    HANDLE hMapping;
#endif

    // Pointer into the shared memory region.
    struct shmem_data* shmem;

    // Count of occurrences per edge
    uint32_t * edge_count;
};

int cov_initialize(struct cov_context*);
void cov_finish_initialization(struct cov_context*, int should_track_edges);
void cov_shutdown(struct cov_context*);

int cov_evaluate(struct cov_context* context, struct edge_set* new_edges);
int cov_evaluate_crash(struct cov_context*);

int cov_compare_equal(struct cov_context*, uint32_t* edges, uint32_t num_edges);

void cov_clear_bitmap(struct cov_context*);

int cov_get_edge_counts(struct cov_context* context, struct edge_counts* edges);
void cov_clear_edge_data(struct cov_context* context, uint32_t index);
void cov_reset_state(struct cov_context* context);

int cov_get_visited_locations(struct cov_context* context, struct edge_set* visited);
int cov_get_visited_types(struct cov_context* context, struct edge_set* visited);
int cov_would_be_interesting(struct cov_context* context, uint32_t location, uint32_t type);
#endif
