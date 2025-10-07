#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 3  // 向量维度固定为3

// 车辆结构体
typedef struct {
    element_t ui, wi;           // 秘密值
    element_t Ui, Wi;           // 公钥组件
    element_t di;               // 私钥组件
    element_t Si, Ki;           // KGC生成的密钥
    element_t y[N];             // 谓词向量
    element_t x[N];             // 隐私信息向量
    char PID[64];               // 伪身份
    
    // Vehicle Joining阶段的凭证
    element_t Ti3, sigma_RVi;
    
    // 临时变量
    element_t ti, tA;
    element_t Ti_temp, Ri;
} Vehicle;

// RSU结构体
typedef struct {
    element_t sA;               // 私钥
    element_t Ppub_A;           // 公钥
} RSU;

// 系统参数
typedef struct {
    element_t g, g0, g1, g2, h;
    element_t alpha;
    element_t u_param;          // u = e(g0, g1)
} SystemParams;

void setup_phase(SystemParams *sys, pairing_t pairing, double *time) {
    double t0 = pbc_get_time();
    
    // 初始化元素
    element_init_G1(sys->g, pairing);
    element_init_G1(sys->g0, pairing);
    element_init_G1(sys->g1, pairing);
    element_init_G1(sys->g2, pairing);
    element_init_G1(sys->h, pairing);
    element_init_Zr(sys->alpha, pairing);
    element_init_GT(sys->u_param, pairing);
    
    // 生成随机参数
    element_random(sys->g);
    element_random(sys->g0);
    element_random(sys->h);
    element_random(sys->alpha);
    
    // 计算 g1 = g^alpha, g2 = g0^alpha
    element_pow_zn(sys->g1, sys->g, sys->alpha);
    element_pow_zn(sys->g2, sys->g0, sys->alpha);
    
    // 计算 u = e(g0, g1)
    pairing_apply(sys->u_param, sys->g0, sys->g1, pairing);
    
    *time = pbc_get_time() - t0;
}

void rsu_setup(RSU *rsu, SystemParams *sys, pairing_t pairing) {
    element_init_Zr(rsu->sA, pairing);
    element_init_G1(rsu->Ppub_A, pairing);
    
    element_random(rsu->sA);
    element_pow_zn(rsu->Ppub_A, sys->g, rsu->sA);
}

void vehicle_registration(Vehicle *v, RSU *rsu, SystemParams *sys, pairing_t pairing) {
    // 初始化车辆元素
    element_init_Zr(v->ui, pairing);
    element_init_Zr(v->wi, pairing);
    element_init_G1(v->Ui, pairing);
    element_init_G1(v->Wi, pairing);
    element_init_Zr(v->di, pairing);
    element_init_G1(v->Si, pairing);
    element_init_G1(v->Ki, pairing);
    
    for (int k = 0; k < N; k++) {
        element_init_Zr(v->y[k], pairing);
        element_init_Zr(v->x[k], pairing);
        element_random(v->y[k]);
        element_random(v->x[k]);
    }
    
    // 车辆选择秘密值
    element_random(v->ui);
    element_pow_zn(v->Ui, sys->g, v->ui);
    
    // RSU生成Wi和di
    element_random(v->wi);
    element_pow_zn(v->Wi, sys->g, v->wi);
    
    // 生成伪身份 (简化处理)
    sprintf(v->PID, "PID_%p", (void*)v);
    
    // 计算 hA1 = H1(...)
    element_t hA1, temp;
    element_init_Zr(hA1, pairing);
    element_init_G1(temp, pairing);
    element_from_hash(hA1, v->PID, strlen(v->PID));
    
    // di = wi + sA * hA1
    element_mul_zn(temp, rsu->Ppub_A, hA1);
    element_mul(v->di, rsu->sA, hA1);
    element_add(v->di, v->wi, v->di);
    
    // KGC生成Si和Ki
    element_t ri, sum_y, temp_pid;
    element_init_Zr(ri, pairing);
    element_init_Zr(sum_y, pairing);
    element_init_Zr(temp_pid, pairing);
    
    element_random(ri);
    element_pow_zn(v->Ki, sys->g, ri);
    
    // 计算 sum(y_ik)
    element_set0(sum_y);
    for (int k = 0; k < N; k++) {
        element_add(sum_y, sum_y, v->y[k]);
    }
    
    // Si = g2^(sum_y) * (g1^PID * h)^ri
    element_from_hash(temp_pid, v->PID, strlen(v->PID));
    element_pow_zn(v->Si, sys->g2, sum_y);
    element_pow_zn(temp, sys->g1, temp_pid);
    element_mul(temp, temp, sys->h);
    element_pow_zn(temp, temp, ri);
    element_mul(v->Si, v->Si, temp);
    
    element_clear(hA1);
    element_clear(temp);
    element_clear(ri);
    element_clear(sum_y);
    element_clear(temp_pid);
}

void vehicle_joining(Vehicle *v, RSU *rsu, SystemParams *sys, pairing_t pairing) {
    element_init_Zr(v->ti, pairing);
    element_init_Zr(v->tA, pairing);
    element_init_G1(v->Ti_temp, pairing);
    element_init_G1(v->Ri, pairing);
    element_init_G1(v->Ti3, pairing);
    element_init_Zr(v->sigma_RVi, pairing);
    
    // 车辆生成临时密钥
    element_random(v->ti);
    element_random(v->tA);
    element_pow_zn(v->Ti_temp, sys->g, v->ti);
    element_pow_zn(v->Ri, sys->g, v->tA);
    
    // RSU生成凭证
    element_t t3, hA2;
    element_init_Zr(t3, pairing);
    element_init_Zr(hA2, pairing);
    
    element_random(t3);
    element_pow_zn(v->Ti3, sys->g, t3);
    
    // hA2 = H5(...)
    char hash_input[128];
    sprintf(hash_input, "hA2_%s", v->PID);
    element_from_hash(hA2, hash_input, strlen(hash_input));
    
    // sigma_R-Vi = t3 + hA2 * sA
    element_mul(v->sigma_RVi, hA2, rsu->sA);
    element_add(v->sigma_RVi, t3, v->sigma_RVi);
    
    element_clear(t3);
    element_clear(hA2);
}

void roaming_authentication(Vehicle *vi, Vehicle *vj, RSU *rsu_A, RSU *rsu_B, SystemParams *sys, pairing_t pairing) {
    // Vi发送消息
    element_t sigma_Vi, hi6, hi7, hA1, hA2;
    element_t C1[N], C2, C3;
    element_t temp1, temp2, temp_pid;
    
    element_init_Zr(sigma_Vi, pairing);
    element_init_Zr(hi6, pairing);
    element_init_Zr(hi7, pairing);
    element_init_Zr(hA1, pairing);
    element_init_Zr(hA2, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_Zr(temp_pid, pairing);
    element_init_G1(C2, pairing);
    element_init_G1(C3, pairing);
    
    for (int k = 0; k < N; k++) {
        element_init_GT(C1[k], pairing);
    }
    
    // 生成签名
    char hash_str[128];
    sprintf(hash_str, "hi6_%s", vi->PID);
    element_from_hash(hi6, hash_str, strlen(hash_str));
    sprintf(hash_str, "hi7_%s", vi->PID);
    element_from_hash(hi7, hash_str, strlen(hash_str));
    sprintf(hash_str, "hA2_%s", vi->PID);
    element_from_hash(hA2, hash_str, strlen(hash_str));
    
    // sigma_Vi = sigma_R-Vi + ti + hi6*ui + hi7*di
    element_set(sigma_Vi, vi->sigma_RVi);
    element_add(sigma_Vi, sigma_Vi, vi->ti);
    element_mul(temp1, hi6, vi->ui);
    element_add(sigma_Vi, sigma_Vi, temp1);
    element_mul(temp1, hi7, vi->di);
    element_add(sigma_Vi, sigma_Vi, temp1);
    
    // 计算密文 C1k = e(g0,g1)^xik * u^ti
    element_pow_zn(C2, sys->g, vi->ti);
    element_from_hash(temp_pid, vj->PID, strlen(vj->PID));
    element_pow_zn(temp1, sys->g1, temp_pid);
    element_mul(temp1, temp1, sys->h);
    element_pow_zn(C3, temp1, vi->ti);
    
    for (int k = 0; k < N; k++) {
        element_t base, exp_part;
        element_init_GT(base, pairing);
        element_init_GT(exp_part, pairing);
        
        pairing_apply(base, sys->g0, sys->g1, pairing);
        element_pow_zn(base, base, vi->x[k]);
        element_pow_zn(exp_part, sys->u_param, vi->ti);
        element_mul(C1[k], base, exp_part);
        
        element_clear(base);
        element_clear(exp_part);
    }
    
    // Vj验证并计算内积
    element_t Q1, Q2, Q3, result;
    element_init_GT(Q1, pairing);
    element_init_GT(Q2, pairing);
    element_init_GT(Q3, pairing);
    element_init_GT(result, pairing);
    
    // Q1 = prod(C1k^yjk)
    element_set1(Q1);
    for (int k = 0; k < N; k++) {
        element_t temp_gt;
        element_init_GT(temp_gt, pairing);
        element_pow_zn(temp_gt, C1[k], vj->y[k]);
        element_mul(Q1, Q1, temp_gt);
        element_clear(temp_gt);
    }
    
    // Q2 = e(C3, Kj)
    pairing_apply(Q2, C3, vj->Ki, pairing);
    
    // Q3 = e(C2, Sj)
    pairing_apply(Q3, C2, vj->Si, pairing);
    
    // result = Q1 * Q2 / Q3
    element_mul(result, Q1, Q2);
    element_div(result, result, Q3);
    
    // 清理
    element_clear(sigma_Vi);
    element_clear(hi6);
    element_clear(hi7);
    element_clear(hA1);
    element_clear(hA2);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp_pid);
    element_clear(C2);
    element_clear(C3);
    element_clear(Q1);
    element_clear(Q2);
    element_clear(Q3);
    element_clear(result);
    
    for (int k = 0; k < N; k++) {
        element_clear(C1[k]);
    }
}

int main(int argc, char **argv) {
    // 首先初始化pairing
    pairing_t pairing;
    pbc_demo_pairing_init(pairing, argc, argv);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");
    
    int vehicle_counts[] = {10, 20, 30};
    
    for (int vc = 0; vc < 3; vc++) {
        int num_vehicles = vehicle_counts[vc];
        printf("\n========================================\n");
        printf("Testing with %d vehicles\n", num_vehicles);
        printf("========================================\n");
        
        SystemParams sys;
        RSU rsu_A, rsu_B;
        Vehicle *vehicles = (Vehicle*)malloc(num_vehicles * sizeof(Vehicle));
        
        double time_setup, time_reg, time_join, time_roam;
        double t0, t1;
        
        // Setup Phase - 传入已初始化的pairing
        setup_phase(&sys, pairing, &time_setup);
        printf("Setup Phase: %.6f s\n", time_setup);
        
        // RSU Setup
        rsu_setup(&rsu_A, &sys, pairing);
        rsu_setup(&rsu_B, &sys, pairing);
        
        // Registration Phase
        t0 = pbc_get_time();
        for (int i = 0; i < num_vehicles; i++) {
            vehicle_registration(&vehicles[i], (i < num_vehicles/2) ? &rsu_A : &rsu_B, &sys, pairing);
        }
        t1 = pbc_get_time();
        time_reg = t1 - t0;
        printf("Registration Phase: %.6f s\n", time_reg);
        
        // Vehicle Join Phase
        t0 = pbc_get_time();
        for (int i = 0; i < num_vehicles; i++) {
            vehicle_joining(&vehicles[i], (i < num_vehicles/2) ? &rsu_A : &rsu_B, &sys, pairing);
        }
        t1 = pbc_get_time();
        time_join = t1 - t0;
        printf("Vehicle_join Phase: %.6f s\n", time_join);
        
        // Roaming Authentication Phase (测试前两个车辆)
        t0 = pbc_get_time();
        if (num_vehicles >= 2) {
            roaming_authentication(&vehicles[0], &vehicles[1], &rsu_A, &rsu_B, &sys, pairing);
        }
        t1 = pbc_get_time();
        time_roam = t1 - t0;
        printf("Roaming_auth Phase: %.6f s\n", time_roam);
        
        double total_time = time_setup + time_reg + time_join + time_roam;
        printf("Total time: %.6f s\n", total_time);
        
        // 清理内存
        for (int i = 0; i < num_vehicles; i++) {
            element_clear(vehicles[i].ui);
            element_clear(vehicles[i].wi);
            element_clear(vehicles[i].Ui);
            element_clear(vehicles[i].Wi);
            element_clear(vehicles[i].di);
            element_clear(vehicles[i].Si);
            element_clear(vehicles[i].Ki);
            element_clear(vehicles[i].ti);
            element_clear(vehicles[i].tA);
            element_clear(vehicles[i].Ti_temp);
            element_clear(vehicles[i].Ri);
            element_clear(vehicles[i].Ti3);
            element_clear(vehicles[i].sigma_RVi);
            for (int k = 0; k < N; k++) {
                element_clear(vehicles[i].y[k]);
                element_clear(vehicles[i].x[k]);
            }
        }
        
        element_clear(rsu_A.sA);
        element_clear(rsu_A.Ppub_A);
        element_clear(rsu_B.sA);
        element_clear(rsu_B.Ppub_A);
        
        element_clear(sys.g);
        element_clear(sys.g0);
        element_clear(sys.g1);
        element_clear(sys.g2);
        element_clear(sys.h);
        element_clear(sys.alpha);
        element_clear(sys.u_param);
        
        free(vehicles);
    }
    
    // 清理主pairing
    pairing_clear(pairing);
    
    printf("\nAll tests completed successfully!\n");
    return 0;
}