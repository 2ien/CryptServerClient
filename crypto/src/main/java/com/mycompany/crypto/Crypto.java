/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.crypto;

import javax.swing.JFrame;

/**
 *
 * @author 2ien
 */
public class Crypto {
    public static void main(String[] args) {
        java.awt.EventQueue.invokeLater(() -> {
           GUI gui = new GUI();
           gui.setLocationRelativeTo(gui);
           gui.setVisible(true);
           gui.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        });
    }
}
